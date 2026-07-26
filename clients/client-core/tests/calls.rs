use client_core::{Client, History, InboundEvent};
use crypto_core::create_account_with_username;

mod common;
use common::spawn_relay;

#[tokio::test]
async fn voice_call_flows_e2e_encrypted_audio_through_the_blind_relay() {
    use client_core::call::{run_call, AudioIo, CallEvent, CallTicket, SAMPLES_PER_FRAME};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = std::sync::Arc::new(Client::new(&base, &ws, &pinned));

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();

    // ── Signaling over the ratchet: Alice rings Bob. ──
    let ticket = CallTicket::mint();
    client
        .send_call_offer(&mut alice, &bob_contact, &ticket.call_id, &ticket.key_b64)
        .await
        .unwrap();

    // Bob's inbox carries the offer — authenticated sender, capability inside.
    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let (call_id, key_b64) = inbox
        .iter()
        .find_map(|e| match e {
            InboundEvent::CallOffered {
                sender_identity_key,
                call_id,
                key_b64,
                ..
            } => {
                assert_eq!(*sender_identity_key, alice.ratchet_ref().identity_key());
                Some((call_id.clone(), key_b64.clone()))
            }
            _ => None,
        })
        .expect("call offer delivered");
    assert_eq!(call_id, ticket.call_id);

    // ── Mock audio: Alice speaks a sine, Bob records what he hears. ──
    struct Sine(f32);
    impl AudioIo for Sine {
        fn read_frame(&mut self, buf: &mut [i16; SAMPLES_PER_FRAME]) -> bool {
            for s in buf.iter_mut() {
                *s = (self.0.sin() * 8000.0) as i16;
                self.0 += 2.0 * std::f32::consts::PI * 440.0 / 48_000.0;
            }
            true
        }
        fn write_frame(&mut self, _frame: &[i16; SAMPLES_PER_FRAME]) {}
    }
    #[derive(Clone)]
    struct Recorder {
        frames: Arc<AtomicUsize>,
        energy: Arc<Mutex<i64>>,
    }
    impl AudioIo for Recorder {
        fn read_frame(&mut self, _buf: &mut [i16; SAMPLES_PER_FRAME]) -> bool {
            false // callee "microphone" silent — engine sends encoded silence
        }
        fn write_frame(&mut self, frame: &[i16; SAMPLES_PER_FRAME]) {
            self.frames.fetch_add(1, Ordering::Relaxed);
            let mut e = self.energy.lock().unwrap();
            *e += frame.iter().map(|s| (*s as i64).abs()).sum::<i64>();
        }
    }
    let recorder = Recorder {
        frames: Arc::new(AtomicUsize::new(0)),
        energy: Arc::new(Mutex::new(0)),
    };

    // ── Both sides join the blind room and run the session — over the explicit
    //    WebSocket fallback, keeping that path covered now that join_call prefers
    //    QUIC (the media e2e below covers QUIC). ──
    let a_media = client.join_call_ws(&ticket.call_id).await.unwrap();
    let b_media = client.join_call_ws(&ticket.call_id).await.unwrap();
    assert_eq!(a_media.transport(), "ws");

    let (a_stop_tx, a_stop_rx) = tokio::sync::watch::channel(false);
    let (b_stop_tx, b_stop_rx) = tokio::sync::watch::channel(false);
    let (a_ev_tx, _a_ev) = tokio::sync::mpsc::unbounded_channel();
    let (b_ev_tx, mut b_ev) = tokio::sync::mpsc::unbounded_channel();
    let unmuted = Arc::new(AtomicBool::new(false));

    let a_key = ticket.key_b64.clone();
    let a_muted = unmuted.clone();
    let a_task = tokio::spawn(async move {
        run_call(
            a_media,
            &a_key,
            true,
            Sine(0.0),
            a_stop_rx,
            a_muted,
            a_ev_tx,
        )
        .await
    });
    let b_key = key_b64.clone();
    let b_rec = recorder.clone();
    let b_muted = unmuted.clone();
    let b_task = tokio::spawn(async move {
        run_call(b_media, &b_key, false, b_rec, b_stop_rx, b_muted, b_ev_tx).await
    });

    // Bob reports Connected once both members are in the room.
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), b_ev.recv())
        .await
        .expect("connected in time")
        .unwrap();
    assert_eq!(first, CallEvent::Connected);

    // Let ~1 s of audio flow, then Alice hangs up.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let _ = a_stop_tx.send(true);
    a_task.await.unwrap().unwrap();

    // Bob observes the peer leaving and his session ends cleanly.
    let mut saw_peer_left = false;
    while let Ok(Some(ev)) =
        tokio::time::timeout(std::time::Duration::from_secs(5), b_ev.recv()).await
    {
        if ev == CallEvent::PeerLeft {
            saw_peer_left = true;
            break;
        }
    }
    assert!(saw_peer_left, "callee must learn the caller hung up");
    let _ = b_stop_tx.send(true);
    let _ = b_task.await;

    // The sine crossed the relay: decrypted, decoded, non-silent, at frame cadence.
    let frames = recorder.frames.load(Ordering::Relaxed);
    assert!(frames >= 30, "expected ≥30 played frames, got {frames}");
    let energy = *recorder.energy.lock().unwrap();
    assert!(
        energy / (frames.max(1) as i64) > 100_000,
        "played audio should be the sine, not silence (avg energy {})",
        energy / (frames.max(1) as i64)
    );
}

#[tokio::test]
async fn video_and_screen_audio_flow_e2e_through_the_blind_relay() {
    use client_core::call::{AudioIo, CallTicket, SAMPLES_PER_FRAME};
    use client_core::media::{
        peer_supports_media2, run_media_call, video, MediaEvent, MediaIo, MediaSink, MediaToggles,
        NoScreenAudio, NoVideo, ScreenAudioSource, Track, VideoSource, SCREEN_AUDIO_SAMPLES,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = std::sync::Arc::new(Client::new(&base, &ws, &pinned));

    let (mut alice, _) = create_account_with_username("carol", "Carol-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("dave", "Dave-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "dave").await.unwrap();

    // ── Signaling: the offer now carries media capabilities inside the ratchet. ──
    let ticket = CallTicket::mint();
    client
        .send_call_offer(&mut alice, &bob_contact, &ticket.call_id, &ticket.key_b64)
        .await
        .unwrap();
    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let (key_b64, caps) = inbox
        .iter()
        .find_map(|e| match e {
            InboundEvent::CallOffered { key_b64, caps, .. } => {
                Some((key_b64.clone(), caps.clone()))
            }
            _ => None,
        })
        .expect("call offer delivered");
    assert!(
        peer_supports_media2(&caps),
        "offer must advertise media2, got {caps:?}"
    );

    // ── Fakes: Alice streams a moving-gradient camera + sine screen audio; both
    //    microphones are silent. Bob records what his sink receives. ──
    struct Silent;
    impl AudioIo for Silent {
        fn read_frame(&mut self, _buf: &mut [i16; SAMPLES_PER_FRAME]) -> bool {
            false
        }
        fn write_frame(&mut self, _frame: &[i16; SAMPLES_PER_FRAME]) {}
    }

    /// ~30 fps camera: yields a fresh 320x240 gradient frame at most every 33 ms.
    struct FakeCamera {
        last: std::time::Instant,
        n: u32,
    }
    impl VideoSource for FakeCamera {
        fn frame(&mut self) -> Option<video::Frame> {
            if self.last.elapsed() < std::time::Duration::from_millis(33) {
                return None;
            }
            self.last = std::time::Instant::now();
            self.n += 1;
            let (w, h) = (320usize, 240usize);
            let mut i420 = vec![128u8; w * h * 3 / 2];
            for y in 0..h {
                for x in 0..w {
                    i420[y * w + x] = ((x + y) as u32 + self.n * 12) as u8;
                }
            }
            Some(video::Frame {
                width: w,
                height: h,
                i420,
            })
        }
    }

    struct SineScreenAudio(f32);
    impl ScreenAudioSource for SineScreenAudio {
        fn read_frame(&mut self, buf: &mut [i16; SCREEN_AUDIO_SAMPLES]) -> bool {
            for pair in buf.chunks_mut(2) {
                let s = (self.0.sin() * 8000.0) as i16;
                for ch in pair {
                    *ch = s;
                }
                self.0 += 2.0 * std::f32::consts::PI * 330.0 / 48_000.0;
            }
            true
        }
    }

    #[derive(Clone, Default)]
    struct RecordingSink {
        cam_frames: Arc<AtomicUsize>,
        cam_pixels_ok: Arc<AtomicUsize>,
        sa_frames: Arc<AtomicUsize>,
        sa_energy: Arc<Mutex<i64>>,
        offs: Arc<Mutex<Vec<Track>>>,
    }
    impl MediaSink for RecordingSink {
        fn video(&mut self, track: Track, frame: video::Frame) {
            if track == Track::Camera {
                self.cam_frames.fetch_add(1, Ordering::Relaxed);
                if frame.width == 320 && frame.height == 240 {
                    self.cam_pixels_ok.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        fn video_off(&mut self, track: Track) {
            self.offs.lock().unwrap().push(track);
        }
        fn screen_audio(&mut self, pcm: &[i16; SCREEN_AUDIO_SAMPLES]) {
            self.sa_frames.fetch_add(1, Ordering::Relaxed);
            *self.sa_energy.lock().unwrap() += pcm.iter().map(|s| (*s as i64).abs()).sum::<i64>();
        }
    }
    struct NullSink;
    impl MediaSink for NullSink {
        fn video(&mut self, _t: Track, _f: video::Frame) {}
        fn video_off(&mut self, _t: Track) {}
        fn screen_audio(&mut self, _p: &[i16; SCREEN_AUDIO_SAMPLES]) {}
    }
    let sink = RecordingSink::default();

    // ── Run the session both ways. Alice starts with camera + screen audio on.
    //    join_call must have silently upgraded both legs to QUIC. ──
    let a_media = client.join_call(&ticket.call_id).await.unwrap();
    let b_media = client.join_call(&ticket.call_id).await.unwrap();
    assert_eq!(
        a_media.transport(),
        "quic",
        "QUIC endpoint advertised — must be used"
    );
    assert_eq!(b_media.transport(), "quic");
    let (a_stop_tx, a_stop_rx) = tokio::sync::watch::channel(false);
    let (b_stop_tx, b_stop_rx) = tokio::sync::watch::channel(false);
    let (a_ev_tx, _a_ev) = tokio::sync::mpsc::unbounded_channel();
    let (b_ev_tx, mut b_ev) = tokio::sync::mpsc::unbounded_channel();

    let a_toggles = MediaToggles::default();
    a_toggles.camera_on.store(true, Ordering::Relaxed);
    a_toggles.screen_audio_on.store(true, Ordering::Relaxed);

    let a_key = ticket.key_b64.clone();
    let a_tg = a_toggles.clone();
    let a_task = tokio::spawn(async move {
        run_media_call(
            a_media,
            &a_key,
            true,
            Arc::new(std::sync::atomic::AtomicBool::new(true)), // Bob's answer advertised media2
            MediaIo {
                audio: Silent,
                camera: FakeCamera {
                    last: std::time::Instant::now(),
                    n: 0,
                },
                screen: NoVideo,
                screen_audio: SineScreenAudio(0.0),
                encoders: None,
                sink: NullSink,
            },
            a_stop_rx,
            a_tg,
            a_ev_tx,
        )
        .await
    });
    let b_key = key_b64.clone();
    let b_sink = sink.clone();
    let b_task = tokio::spawn(async move {
        run_media_call(
            b_media,
            &b_key,
            false,
            Arc::new(std::sync::atomic::AtomicBool::new(true)), // Alice's offer advertised media2
            MediaIo {
                audio: Silent,
                camera: NoVideo,
                screen: NoVideo,
                screen_audio: NoScreenAudio,
                encoders: None,
                sink: b_sink,
            },
            b_stop_rx,
            MediaToggles::default(),
            b_ev_tx,
        )
        .await
    });

    // Bob learns video is available on this call, connects, and sees Alice's tracks
    // announce themselves.
    let mut saw_ready = false;
    let mut saw_connected = false;
    let mut saw_cam_on = false;
    let mut saw_sa_on = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !(saw_ready && saw_connected && saw_cam_on && saw_sa_on) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let ev = tokio::time::timeout(remaining, b_ev.recv())
            .await
            .expect("media events in time")
            .unwrap();
        match ev {
            MediaEvent::VideoReady(ok) => saw_ready = ok,
            MediaEvent::Connected => saw_connected = true,
            MediaEvent::PeerTrack {
                track: Track::Camera,
                on: true,
            } => saw_cam_on = true,
            MediaEvent::PeerTrack {
                track: Track::ScreenAudio,
                on: true,
            } => saw_sa_on = true,
            _ => {}
        }
    }

    // Let ~1.5 s of media flow.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // Alice turns the camera off — Bob's UI hears about it both ways.
    a_toggles.camera_on.store(false, Ordering::Relaxed);
    let mut saw_cam_off = false;
    while let Ok(Some(ev)) =
        tokio::time::timeout(std::time::Duration::from_secs(5), b_ev.recv()).await
    {
        if let MediaEvent::PeerTrack {
            track: Track::Camera,
            on: false,
        } = ev
        {
            saw_cam_off = true;
            break;
        }
    }
    assert!(saw_cam_off, "camera-off must reach the peer");
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if sink.offs.lock().unwrap().contains(&Track::Camera) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .is_ok(),
        "sink must be told to hide the camera tile"
    );

    // Hang up; both sessions end cleanly.
    let _ = a_stop_tx.send(true);
    a_task.await.unwrap().unwrap();
    let mut saw_peer_left = false;
    while let Ok(Some(ev)) =
        tokio::time::timeout(std::time::Duration::from_secs(5), b_ev.recv()).await
    {
        if ev == MediaEvent::PeerLeft {
            saw_peer_left = true;
            break;
        }
    }
    assert!(saw_peer_left, "callee must learn the caller hung up");
    let _ = b_stop_tx.send(true);
    let _ = b_task.await;

    // Camera video crossed the relay decrypted + decoded at the right size, at a
    // plausible frame rate; screen audio arrived and was not silence.
    let cam = sink.cam_frames.load(Ordering::Relaxed);
    assert!(cam >= 15, "expected ≥15 decoded camera frames, got {cam}");
    assert_eq!(sink.cam_pixels_ok.load(Ordering::Relaxed), cam);
    let sa = sink.sa_frames.load(Ordering::Relaxed);
    assert!(sa >= 30, "expected ≥30 screen-audio frames, got {sa}");
    let sa_energy = *sink.sa_energy.lock().unwrap() / (sa.max(1) as i64);
    assert!(
        sa_energy > 100_000,
        "screen audio should be the sine, not silence (avg energy {sa_energy})"
    );
}

/// Ring-all-devices, end to end: a call offer reaches every device of a linked account
/// (same call id + key), the answering device's self-sync tells its sibling to stop
/// ringing, busy declines are marked so the caller can keep ringing other devices, and a
/// cancel fans out so no device rings into the timeout.
#[tokio::test]
async fn call_ring_reaches_all_devices_and_first_answer_wins() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut alice_hist = History::new();
    let mut bob_hist = History::new();

    // Link alice's second device.
    let (mut alice2, _) = create_account_with_username("alice", "Device2-Password-99!").unwrap();
    let req = client.create_link_request(&alice2);
    client
        .authorize_link(&alice, &mut alice_hist, &req, "Alice-Password-123!")
        .await
        .unwrap();
    let linked = client
        .complete_link(&mut alice2, &req, "Alice-Password-123!")
        .await
        .unwrap();
    let alice2_hist = linked.history;
    let alice2_mailbox = client.device_mailbox("alice", &req.device_id).unwrap();
    // Drain the link-time hello so the primary shares alice2's session.
    let _ = client.fetch_inbox(&mut alice).await.unwrap();

    // ── Bob rings "alice": direct offer to the primary + one extra roster copy. ──
    let alice_contact = client.add_contact(&mut bob, "alice").await.unwrap();
    let ticket = client_core::call::CallTicket::mint();
    client
        .send_call_offer(&mut bob, &alice_contact, &ticket.call_id, &ticket.key_b64)
        .await
        .unwrap();
    let extras = client
        .extra_call_offer_envelopes(
            &mut bob,
            &mut bob_hist,
            &alice_contact,
            &ticket.call_id,
            &ticket.key_b64,
        )
        .await
        .unwrap();
    assert_eq!(extras.len(), 1, "one extra copy for the linked device");
    client.post_envelopes(&extras).await.unwrap();

    // Both devices ring with the SAME call id and key.
    let offer_on = |inbox: &[InboundEvent]| {
        inbox.iter().find_map(|e| match e {
            InboundEvent::CallOffered {
                call_id, key_b64, ..
            } => Some((call_id.clone(), key_b64.clone())),
            _ => None,
        })
    };
    let inbox1 = client.fetch_inbox(&mut alice).await.unwrap();
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert_eq!(
        offer_on(&inbox1),
        Some((ticket.call_id.clone(), ticket.key_b64.clone()))
    );
    assert_eq!(
        offer_on(&inbox2),
        Some((ticket.call_id.clone(), ticket.key_b64.clone()))
    );

    // ── Primary answers; its self-sync stops the sibling's ring. ──
    let bob_key = bob.ratchet_ref().identity_key();
    client
        .send_call_answer(
            &mut alice,
            &client_core::contact_for("bob", &bob_key),
            &ticket.call_id,
            true,
            false,
        )
        .await
        .unwrap();
    let handled = client
        .call_handled_selfsync(&mut alice, &mut alice_hist, &ticket.call_id)
        .await
        .unwrap();
    assert_eq!(handled.len(), 1, "one handled notice to the linked device");
    client.post_envelopes(&handled).await.unwrap();

    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    let handled_from = inbox2
        .iter()
        .find_map(|e| match e {
            InboundEvent::SelfCallHandled {
                sender_identity_key,
                call_id,
            } if *call_id == ticket.call_id => Some(sender_identity_key.clone()),
            _ => None,
        })
        .expect("linked device must receive the handled notice");
    assert!(
        alice2_hist.is_own_device(&handled_from),
        "handled notice must authenticate as our own device"
    );

    // Bob sees an explicit (non-busy) accept.
    let bob_inbox = client.fetch_inbox(&mut bob).await.unwrap();
    assert!(bob_inbox.iter().any(|e| matches!(e,
        InboundEvent::CallAnswered { call_id, accept: true, busy: false, .. }
            if *call_id == ticket.call_id)));

    // ── Busy decline is marked so the caller can keep ringing other devices. ──
    client
        .send_call_answer(
            &mut alice2,
            &client_core::contact_for("bob", &bob_key),
            "some-other-call",
            false,
            true,
        )
        .await
        .unwrap();
    let bob_inbox = client.fetch_inbox(&mut bob).await.unwrap();
    assert!(bob_inbox.iter().any(|e| matches!(e,
        InboundEvent::CallAnswered { call_id, accept: false, busy: true, .. }
            if call_id == "some-other-call")));

    // ── Answers reach a caller on a LINKED device. ──
    // The direct 1:1 answer goes to the caller's ACCOUNT mailbox (only the primary
    // drains that), so when the call was placed from alice's LINKED device, the fan
    // copy on that device's own mailbox is the only answer it can receive.
    let ticket2 = client_core::call::CallTicket::mint();
    let bob_contact_for_alice2 = client_core::contact_for("bob", &bob_key);
    client
        .send_call_offer(
            &mut alice2,
            &bob_contact_for_alice2,
            &ticket2.call_id,
            &ticket2.key_b64,
        )
        .await
        .unwrap();
    let _ = client.fetch_inbox(&mut bob).await.unwrap(); // bob sees the ring
    let alice_contact_linked =
        client_core::contact_for("alice", &alice2.ratchet_ref().identity_key());
    client
        .send_call_answer(
            &mut bob,
            &alice_contact_linked,
            &ticket2.call_id,
            true,
            false,
        )
        .await
        .unwrap();
    let answer_fan = client
        .extra_call_answer_envelopes(
            &mut bob,
            &mut bob_hist,
            &alice_contact_linked,
            &ticket2.call_id,
            true,
            false,
        )
        .await
        .unwrap();
    // The directly-addressed key is NOT the primary, so every device gets a fan copy.
    assert_eq!(answer_fan.len(), 2);
    client.post_envelopes(&answer_fan).await.unwrap();
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert!(
        inbox2.iter().any(|e| matches!(e,
            InboundEvent::CallAnswered { call_id, accept: true, .. }
                if *call_id == ticket2.call_id)),
        "the linked caller must receive the accept on its own mailbox"
    );

    // ── A cancel fans out too, so no device rings into the timeout. ──
    let end_extras = client
        .extra_call_end_envelopes(&mut bob, &mut bob_hist, &alice_contact, &ticket.call_id)
        .await
        .unwrap();
    assert_eq!(end_extras.len(), 1);
    client.post_envelopes(&end_extras).await.unwrap();
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert!(inbox2.iter().any(|e| matches!(e,
        InboundEvent::CallEnded { call_id, .. } if *call_id == ticket.call_id)));
}

#[tokio::test]
async fn group_call_meshes_three_parties_through_blind_pair_rooms() {
    use client_core::call::{AudioIo, CallTicket, SAMPLES_PER_FRAME};
    use client_core::groupcall::{run_group_call, GroupCallEvent, GroupLeg};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Arc::new(Client::new(&base, &ws, &pinned));

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    let (mut carol, _) = create_account_with_username("carol", "Carol-Password-789!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    client.register(&mut carol, 5).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();
    let carol_contact = client.add_contact(&mut alice, "carol").await.unwrap();

    // A group with the three of them.
    let (group, _epoch) = client
        .create_group(
            &mut alice,
            "trio",
            &[bob_contact.clone(), carol_contact.clone()],
        )
        .await
        .unwrap();

    // ── Signaling: Alice starts the call — one fresh ticket per pair leg, each sent
    //    only inside that pair's ratchet session. ──
    let instance = {
        let mut b = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    };
    let t_ab = CallTicket::mint();
    let t_ac = CallTicket::mint();
    client
        .send_group_call_offer(
            &mut alice,
            &bob_contact,
            &group.id,
            &instance,
            &t_ab.call_id,
            &t_ab.key_b64,
        )
        .await
        .unwrap();
    client
        .send_group_call_offer(
            &mut alice,
            &carol_contact,
            &group.id,
            &instance,
            &t_ac.call_id,
            &t_ac.key_b64,
        )
        .await
        .unwrap();

    // Bob and Carol each receive exactly their own leg's capability.
    let take_offer = |inbox: &[InboundEvent]| {
        inbox
            .iter()
            .find_map(|e| match e {
                InboundEvent::GroupCallOffered {
                    sender_identity_key,
                    call_instance,
                    call_id,
                    key_b64,
                    group_id,
                    ..
                } => {
                    assert_eq!(*sender_identity_key, alice.ratchet_ref().identity_key());
                    assert_eq!(*call_instance, instance);
                    assert_eq!(*group_id, group.id);
                    Some((call_id.clone(), key_b64.clone()))
                }
                _ => None,
            })
            .expect("group call offer delivered")
    };
    let bob_inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let (bob_call_id, bob_key) = take_offer(&bob_inbox);
    assert_eq!(bob_call_id, t_ab.call_id);
    let carol_inbox = client.fetch_inbox(&mut carol).await.unwrap();
    let (carol_call_id, carol_key) = take_offer(&carol_inbox);
    assert_eq!(carol_call_id, t_ac.call_id);
    // Keys are per-pair: Bob's capability opens nothing of Carol's leg.
    assert_ne!(bob_call_id, carol_call_id);
    assert_ne!(bob_key, carol_key);

    // On accept, Bob (as pair owner or not — deterministic glare rule; here Bob mints,
    // being one side of the remaining pair) offers Carol their direct leg.
    let bob_carol_contact = client.add_contact(&mut bob, "carol").await.unwrap();
    let t_bc = CallTicket::mint();
    client
        .send_group_call_offer(
            &mut bob,
            &bob_carol_contact,
            &group.id,
            &instance,
            &t_bc.call_id,
            &t_bc.key_b64,
        )
        .await
        .unwrap();
    let carol_inbox2 = client.fetch_inbox(&mut carol).await.unwrap();
    let (bc_call_id, bc_key) = carol_inbox2
        .iter()
        .find_map(|e| match e {
            InboundEvent::GroupCallOffered {
                call_id,
                key_b64,
                call_instance,
                ..
            } if *call_instance == instance && *call_id != carol_call_id => {
                Some((call_id.clone(), key_b64.clone()))
            }
            _ => None,
        })
        .expect("bob->carol leg offer delivered");
    assert_eq!(bc_call_id, t_bc.call_id);

    // ── Media: three engines, each with its two pair legs (a full mesh). ──
    struct Sine(f32, f32); // phase, freq — every party speaks a distinct tone
    impl AudioIo for Sine {
        fn read_frame(&mut self, buf: &mut [i16; SAMPLES_PER_FRAME]) -> bool {
            for s in buf.iter_mut() {
                *s = (self.0.sin() * 6000.0) as i16;
                self.0 += 2.0 * std::f32::consts::PI * self.1 / 48_000.0;
            }
            true
        }
        fn write_frame(&mut self, _f: &[i16; SAMPLES_PER_FRAME]) {}
    }
    #[derive(Clone)]
    struct Recorder {
        frames: Arc<AtomicUsize>,
        energy: Arc<Mutex<i64>>,
        tone: f32,
    }
    impl AudioIo for Recorder {
        fn read_frame(&mut self, buf: &mut [i16; SAMPLES_PER_FRAME]) -> bool {
            for s in buf.iter_mut() {
                *s = (self.tone.sin() * 6000.0) as i16;
                self.tone += 2.0 * std::f32::consts::PI * 660.0 / 48_000.0;
            }
            true
        }
        fn write_frame(&mut self, frame: &[i16; SAMPLES_PER_FRAME]) {
            self.frames.fetch_add(1, Ordering::Relaxed);
            *self.energy.lock().unwrap() += frame.iter().map(|s| (*s as i64).abs()).sum::<i64>();
        }
    }

    let mk_leg = |media, peer: &str, key: &str, caller| GroupLeg {
        peer_key: peer.to_string(),
        media,
        key_b64: key.to_string(),
        caller,
    };
    // Join every pair room over the explicit WS fallback (deterministic in tests).
    let a_b = client.join_call_ws(&t_ab.call_id).await.unwrap();
    let b_a = client.join_call_ws(&t_ab.call_id).await.unwrap();
    let a_c = client.join_call_ws(&t_ac.call_id).await.unwrap();
    let c_a = client.join_call_ws(&t_ac.call_id).await.unwrap();
    let b_c = client.join_call_ws(&t_bc.call_id).await.unwrap();
    let c_b = client.join_call_ws(&t_bc.call_id).await.unwrap();

    let spawn_engine = |legs: Vec<GroupLeg>, audio: Box<dyn FnOnce() -> EngineAudio + Send>| {
        let (leg_tx, leg_rx) = tokio::sync::mpsc::unbounded_channel();
        for l in legs {
            leg_tx.send(l).unwrap();
        }
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (ev_tx, ev_rx) = tokio::sync::mpsc::unbounded_channel();
        let muted = Arc::new(AtomicBool::new(false));
        let m = muted.clone();
        let task = tokio::spawn(async move {
            match audio() {
                EngineAudio::Sine(s) => run_group_call(leg_rx, s, stop_rx, m, ev_tx).await,
                EngineAudio::Rec(r) => run_group_call(leg_rx, r, stop_rx, m, ev_tx).await,
            }
        });
        (leg_tx, stop_tx, ev_rx, task)
    };
    enum EngineAudio {
        Sine(Sine),
        Rec(Recorder),
    }

    let bob_rec = Recorder {
        frames: Arc::new(AtomicUsize::new(0)),
        energy: Arc::new(Mutex::new(0)),
        tone: 0.0,
    };
    let carol_rec = Recorder {
        frames: Arc::new(AtomicUsize::new(0)),
        energy: Arc::new(Mutex::new(0)),
        tone: 0.5,
    };

    let alice_key_id = alice.ratchet_ref().identity_key();
    let bob_key_id = bob.ratchet_ref().identity_key();
    let carol_key_id = carol.ratchet_ref().identity_key();

    // Alice owns (caller=true) both of her legs; Bob owns the B–C leg.
    let (_a_legs, a_stop, _a_ev, a_task) = spawn_engine(
        vec![
            mk_leg(a_b, &bob_key_id, &t_ab.key_b64, true),
            mk_leg(a_c, &carol_key_id, &t_ac.key_b64, true),
        ],
        Box::new(|| EngineAudio::Sine(Sine(0.0, 440.0))),
    );
    let br = bob_rec.clone();
    let (_b_legs, b_stop, mut b_ev, b_task) = spawn_engine(
        vec![
            mk_leg(b_a, &alice_key_id, &bob_key, false),
            mk_leg(b_c, &carol_key_id, &t_bc.key_b64, true),
        ],
        Box::new(move || EngineAudio::Rec(br)),
    );
    let cr = carol_rec.clone();
    let (_c_legs, c_stop, mut c_ev, c_task) = spawn_engine(
        vec![
            mk_leg(c_a, &alice_key_id, &carol_key, false),
            mk_leg(c_b, &bob_key_id, &bc_key, false),
        ],
        Box::new(move || EngineAudio::Rec(cr)),
    );

    // Bob and Carol each hear BOTH other parties (per-peer connect events).
    async fn expect_connected(
        ev_rx: &mut tokio::sync::mpsc::UnboundedReceiver<GroupCallEvent>,
        want: Vec<String>,
    ) {
        let mut seen = std::collections::HashSet::new();
        while seen.len() < want.len() {
            let ev = tokio::time::timeout(std::time::Duration::from_secs(10), ev_rx.recv())
                .await
                .expect("peer connected in time")
                .unwrap();
            if let GroupCallEvent::PeerConnected { peer_key } = ev {
                assert!(want.contains(&peer_key), "unexpected peer {peer_key}");
                seen.insert(peer_key);
            }
        }
    }
    expect_connected(&mut b_ev, vec![alice_key_id.clone(), carol_key_id.clone()]).await;
    expect_connected(&mut c_ev, vec![alice_key_id.clone(), bob_key_id.clone()]).await;

    // Let ~1 s of mixed audio flow.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let bob_frames = bob_rec.frames.load(Ordering::Relaxed);
    let bob_energy = *bob_rec.energy.lock().unwrap();
    assert!(bob_frames >= 30, "bob played only {bob_frames} frames");
    assert!(bob_energy > 0, "bob heard silence — mixing/decrypt broken");
    let carol_energy = *carol_rec.energy.lock().unwrap();
    assert!(carol_energy > 0, "carol heard silence");

    // ── Alice hangs up: both her legs die; Bob & Carol stay connected to each other. ──
    let _ = a_stop.send(true);
    a_task.await.unwrap().unwrap();
    let saw_alice_leave = async {
        loop {
            let ev = tokio::time::timeout(std::time::Duration::from_secs(5), b_ev.recv())
                .await
                .expect("leave event in time")
                .unwrap();
            if matches!(&ev, GroupCallEvent::PeerLeft { peer_key } if *peer_key == alice_key_id) {
                break;
            }
        }
    };
    saw_alice_leave.await;

    // B–C keeps flowing after A left.
    let before = carol_rec.frames.load(Ordering::Relaxed);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let after = carol_rec.frames.load(Ordering::Relaxed);
    assert!(after > before, "carol's audio stopped when alice left");

    // ── A comes back mid-call: FRESH tickets (a room key is used once, ever), legs
    //    fed into B's and C's RUNNING engines — the drop-and-re-establish path. ──
    let t_ab2 = CallTicket::mint();
    let t_ac2 = CallTicket::mint();
    assert_ne!(t_ab2.call_id, t_ab.call_id, "rejoin must mint a fresh room");
    let a_b2 = client.join_call_ws(&t_ab2.call_id).await.unwrap();
    let b_a2 = client.join_call_ws(&t_ab2.call_id).await.unwrap();
    let a_c2 = client.join_call_ws(&t_ac2.call_id).await.unwrap();
    let c_a2 = client.join_call_ws(&t_ac2.call_id).await.unwrap();
    let (_a2_legs, a2_stop, _a2_ev, a2_task) = spawn_engine(
        vec![
            mk_leg(a_b2, &bob_key_id, &t_ab2.key_b64, true),
            mk_leg(a_c2, &carol_key_id, &t_ac2.key_b64, true),
        ],
        Box::new(|| EngineAudio::Sine(Sine(0.0, 440.0))),
    );
    _b_legs
        .send(mk_leg(b_a2, &alice_key_id, &t_ab2.key_b64, false))
        .unwrap();
    _c_legs
        .send(mk_leg(c_a2, &alice_key_id, &t_ac2.key_b64, false))
        .unwrap();
    // Bob's running engine reports Alice connected again on the new leg.
    expect_connected(&mut b_ev, vec![alice_key_id.clone()]).await;
    let _ = a2_stop.send(true);
    let _ = a2_task.await;

    // And the decline/leave signal is a plain E2E payload.
    client
        .send_group_call_end(&mut bob, &bob_carol_contact, &group.id, &instance)
        .await
        .unwrap();
    let carol_inbox3 = client.fetch_inbox(&mut carol).await.unwrap();
    assert!(carol_inbox3.iter().any(|e| matches!(e,
        InboundEvent::GroupCallEnded { call_instance, .. } if *call_instance == instance)));

    let _ = b_stop.send(true);
    let _ = c_stop.send(true);
    let _ = b_task.await;
    let _ = c_task.await;
}

#[tokio::test]
async fn reconnect_offer_carries_marker_and_normal_offers_do_not() {
    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let bob_contact = client.add_contact(&mut alice, "bob").await.unwrap();

    // A normal ring: no reconnect marker.
    let first = client_core::call::CallTicket::mint();
    client
        .send_call_offer(&mut alice, &bob_contact, &first.call_id, &first.key_b64)
        .await
        .unwrap();
    // The silent resume of that call: FRESH room id + key, marker names the old call.
    let resumed = client_core::call::CallTicket::mint();
    client
        .send_call_offer_full(
            &mut alice,
            &bob_contact,
            &resumed.call_id,
            &resumed.key_b64,
            &first.call_id,
        )
        .await
        .unwrap();

    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let offers: Vec<(String, String)> = inbox
        .iter()
        .filter_map(|e| match e {
            InboundEvent::CallOffered {
                call_id,
                reconnect_of,
                ..
            } => Some((call_id.clone(), reconnect_of.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(offers.len(), 2);
    assert_eq!(offers[0], (first.call_id.clone(), String::new()));
    assert_eq!(offers[1], (resumed.call_id.clone(), first.call_id.clone()));
    // The resume never reuses the old room or key.
    assert_ne!(resumed.call_id, first.call_id);
    assert_ne!(resumed.key_b64, first.key_b64);
}
