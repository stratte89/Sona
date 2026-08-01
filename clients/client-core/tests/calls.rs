use client_core::{Client, History, InboundEvent};
use crypto_core::create_account_with_username;

mod common;
use common::spawn_relay;

fn signal_times() -> (u64, u64, u64) {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (
        created_at,
        created_at + client_core::callstate::CALL_RING_TIMEOUT_SECS,
        created_at + client_core::callstate::CALL_SIGNAL_TTL_SECS,
    )
}

fn signal_id(byte: u8) -> String {
    format!("{byte:02x}").repeat(16)
}

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
    let (created_at, ring_expires_at, expires_at) = signal_times();
    client
        .send_call_offer_v2(
            &mut alice,
            &bob_contact,
            &signal_id(1),
            &signal_id(2),
            &ticket.call_id,
            &ticket.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            "",
        )
        .await
        .unwrap();

    // Bob's inbox carries the offer — authenticated sender, capability inside.
    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let (call_id, key_b64) = inbox
        .iter()
        .find_map(|e| match e {
            InboundEvent::CallOfferedV2 {
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
    let (created_at, ring_expires_at, expires_at) = signal_times();
    client
        .send_call_offer_v2(
            &mut alice,
            &bob_contact,
            &signal_id(3),
            &signal_id(4),
            &ticket.call_id,
            &ticket.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            "",
        )
        .await
        .unwrap();
    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let (key_b64, caps) = inbox
        .iter()
        .find_map(|e| match e {
            InboundEvent::CallOfferedV2 { key_b64, caps, .. } => {
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
    // E-7: room membership and audio that actually opened are different claims, and only
    // the second one may be shown to a user as "connected". A `caller`-flag disagreement
    // satisfies the first and never the second, in both directions at once, which is what
    // "the timer ran and neither of us could hear anything" was.
    let mut saw_voice = false;
    let mut saw_cam_on = false;
    let mut saw_sa_on = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !(saw_ready && saw_connected && saw_voice && saw_cam_on && saw_sa_on) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let ev = tokio::time::timeout(remaining, b_ev.recv())
            .await
            .expect("media events in time")
            .unwrap();
        match ev {
            MediaEvent::VideoReady(ok) => saw_ready = ok,
            MediaEvent::Connected => saw_connected = true,
            MediaEvent::VoiceFlowing => saw_voice = true,
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

/// Ring-all-devices, end to end: both devices receive the same logical offer, competing
/// claims stay explicit, one caller-issued winner reaches every device, the winning
/// device self-syncs a terminal tombstone, busy remains non-terminal, and cancellation
/// uses the urgent terminal family.
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
    let call_instance_id = signal_id(10);
    let offer_id = signal_id(11);
    let (created_at, ring_expires_at, expires_at) = signal_times();
    let primary = client
        .prepare_call_offer_v2(
            &mut bob,
            &alice_contact,
            &call_instance_id,
            &offer_id,
            &ticket.call_id,
            &ticket.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            "",
        )
        .unwrap();
    // The fan is network-free: warming resolves alice's verified roster and opens the
    // linked device's session first, exactly as the shell does off-lock before a call.
    client
        .warm_account_routes(&mut bob, &mut bob_hist, "alice")
        .await
        .unwrap();
    let mut extras = client
        .extra_call_offer_envelopes_v2(
            &mut bob,
            &bob_hist,
            &alice_contact,
            &call_instance_id,
            &offer_id,
            &ticket.call_id,
            &ticket.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            "",
        )
        .unwrap();
    assert_eq!(extras.len(), 1, "one extra copy for the linked device");
    let mut fanout = vec![primary];
    fanout.append(&mut extras);
    let results = client.post_envelopes_concurrent(&fanout).await;
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(Result::is_ok));

    // Both devices ring with the same logical IDs and media capability.
    let offer_on = |inbox: &[InboundEvent]| {
        inbox.iter().find_map(|e| match e {
            InboundEvent::CallOfferedV2 {
                call_instance_id,
                offer_id,
                call_id,
                key_b64,
                expires_at,
                ..
            } => Some((
                call_instance_id.clone(),
                offer_id.clone(),
                call_id.clone(),
                key_b64.clone(),
                *expires_at,
            )),
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
        Some((
            call_instance_id.clone(),
            offer_id.clone(),
            ticket.call_id.clone(),
            ticket.key_b64.clone(),
            expires_at,
        ))
    );
    assert_eq!(
        offer_on(&inbox2),
        Some((
            call_instance_id.clone(),
            offer_id.clone(),
            ticket.call_id.clone(),
            ticket.key_b64.clone(),
            expires_at,
        ))
    );

    // ── Both devices race to answer; Bob receives two explicit claims. ──
    let bob_key = bob.ratchet_ref().identity_key();
    let bob_contact_for_alice = client_core::contact_for("bob", &bob_key);
    let primary_nonce = signal_id(12);
    let linked_nonce = signal_id(13);
    let primary_mailbox = client.device_mailbox("alice", "0").unwrap();
    let bob_reply = client.device_mailbox("bob", "0").unwrap();
    let primary_claim = client
        .prepare_call_answer_claim_v2_to_mailbox(
            &mut alice,
            &bob_key,
            &bob_reply,
            &call_instance_id,
            &offer_id,
            &primary_nonce,
            "0",
            &primary_mailbox,
            expires_at,
        )
        .unwrap();
    let linked_claim = client
        .prepare_call_answer_claim_v2_to_mailbox(
            &mut alice2,
            &bob_key,
            &bob_reply,
            &call_instance_id,
            &offer_id,
            &linked_nonce,
            &req.device_id,
            &alice2_mailbox,
            expires_at,
        )
        .unwrap();
    client.post_envelope(&primary_claim).await.unwrap();
    client.post_envelope(&linked_claim).await.unwrap();
    let bob_inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let claims: Vec<_> = bob_inbox
        .iter()
        .filter_map(|event| match event {
            InboundEvent::CallAnswerClaimedV2 {
                claim_nonce,
                answering_device_id,
                ..
            } => Some((claim_nonce.clone(), answering_device_id.clone())),
            _ => None,
        })
        .collect();
    assert!(claims.contains(&(primary_nonce.clone(), "0".to_string())));
    assert!(claims.contains(&(linked_nonce, req.device_id.clone())));

    // Bob chooses the primary and broadcasts the one winner to every verified device.
    let winner = client
        .prepare_call_winner_v2_to_mailbox(
            &mut bob,
            &alice.ratchet_ref().identity_key(),
            &primary_mailbox,
            &call_instance_id,
            &offer_id,
            &primary_nonce,
            "0",
            expires_at,
        )
        .unwrap();
    client.post_envelope(&winner).await.unwrap();
    let winner_fan = client
        .extra_call_winner_envelopes_v2(
            &mut bob,
            &bob_hist,
            &alice_contact,
            &call_instance_id,
            &offer_id,
            &primary_nonce,
            "0",
            expires_at,
        )
        .unwrap();
    assert_eq!(winner_fan.len(), 1);
    client.post_envelopes(&winner_fan).await.unwrap();
    let winner_on = |inbox: &[InboundEvent]| {
        inbox.iter().any(|event| {
            matches!(
                event,
                InboundEvent::CallWinnerV2 {
                    call_instance_id: got_call,
                    claim_nonce,
                    winner_device_id,
                    ..
                } if got_call == &call_instance_id
                    && claim_nonce == &primary_nonce
                    && winner_device_id == "0"
            )
        })
    };
    let inbox1 = client.fetch_inbox(&mut alice).await.unwrap();
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert!(winner_on(&inbox1));
    assert!(winner_on(&inbox2));

    // The winner's explicit sibling terminal authenticates as our own device.
    client
        .warm_account_routes(&mut alice, &mut alice_hist, "alice")
        .await
        .unwrap();
    let handled = client
        .call_terminal_selfsync_v2(
            &mut alice,
            &alice_hist,
            &call_instance_id,
            &offer_id,
            client_core::callstate::CallTerminalReason::AnsweredElsewhere,
            "0",
            expires_at,
        )
        .unwrap();
    assert_eq!(handled.len(), 1);
    client.post_envelopes(&handled).await.unwrap();
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    let handled_from = inbox2
        .iter()
        .find_map(|event| match event {
            InboundEvent::SelfCallTerminalV2 {
                sender_identity_key,
                call_instance_id: got_call,
                reason: client_core::callstate::CallTerminalReason::AnsweredElsewhere,
                ..
            } if got_call == &call_instance_id => Some(sender_identity_key.clone()),
            _ => None,
        })
        .expect("linked device receives terminal self-sync");
    assert!(alice2_hist.is_own_device(&handled_from));

    // Busy is its own non-terminal message, so the caller may keep sibling rings live.
    let busy = client
        .prepare_call_busy_v2_to_mailbox(
            &mut alice2,
            &bob_key,
            &bob_reply,
            &signal_id(20),
            &signal_id(21),
            &req.device_id,
            expires_at,
        )
        .unwrap();
    client.post_envelope(&busy).await.unwrap();
    let bob_inbox = client.fetch_inbox(&mut bob).await.unwrap();
    assert!(bob_inbox.iter().any(|event| matches!(
        event,
        InboundEvent::CallBusyV2 {
            call_instance_id,
            device_id,
            ..
        } if call_instance_id == &signal_id(20) && device_id == &req.device_id
    )));

    // Cancellation fans out as an explicit terminal control.
    let end_extras = client
        .extra_call_terminal_envelopes_v2(
            &mut bob,
            &bob_hist,
            &alice_contact,
            &call_instance_id,
            &offer_id,
            client_core::callstate::CallTerminalReason::CallerCancelled,
            "0",
            expires_at,
        )
        .unwrap();
    assert_eq!(end_extras.len(), 1);
    client.post_envelopes(&end_extras).await.unwrap();
    let inbox2 = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert!(inbox2.iter().any(|event| matches!(
        event,
        InboundEvent::CallTerminalV2 {
            call_instance_id: got_call,
            sender_username,
            reason: client_core::callstate::CallTerminalReason::CallerCancelled,
            ..
        } if got_call == &call_instance_id && sender_username == "bob"
    )));

    // A linked caller advertises its exact device mailbox. Bob's answer claim goes only
    // there—not to Alice's primary account mailbox—and Alice2 routes the winner back to
    // Bob's exact mailbox from the claim.
    let linked_call = signal_id(22);
    let linked_offer = signal_id(23);
    let linked_ticket = client_core::call::CallTicket::mint();
    let (created_at, ring_expires_at, expires_at) = signal_times();
    let offer = client
        .prepare_call_offer_v2(
            &mut alice2,
            &bob_contact_for_alice,
            &linked_call,
            &linked_offer,
            &linked_ticket.call_id,
            &linked_ticket.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            &req.device_id,
            "",
        )
        .unwrap();
    client.post_envelope(&offer).await.unwrap();
    let bob_inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let routed_caller = bob_inbox
        .iter()
        .find_map(|event| match event {
            InboundEvent::CallOfferedV2 {
                sender_identity_key,
                call_instance_id,
                reply_to_mailbox,
                ..
            } if call_instance_id == &linked_call => {
                Some((sender_identity_key.clone(), reply_to_mailbox.clone()))
            }
            _ => None,
        })
        .expect("linked caller offer");
    assert_eq!(routed_caller.0, alice2.ratchet_ref().identity_key());
    assert_eq!(routed_caller.1, alice2_mailbox);

    let linked_claim = signal_id(24);
    let claim = client
        .prepare_call_answer_claim_v2_to_mailbox(
            &mut bob,
            &routed_caller.0,
            &routed_caller.1,
            &linked_call,
            &linked_offer,
            &linked_claim,
            "0",
            &bob_reply,
            expires_at,
        )
        .unwrap();
    client.post_envelope(&claim).await.unwrap();
    let linked_inbox = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert!(linked_inbox.iter().any(|event| matches!(
        event,
        InboundEvent::CallAnswerClaimedV2 {
            call_instance_id,
            claim_nonce,
            ..
        } if call_instance_id == &linked_call && claim_nonce == &linked_claim
    )));
    let primary_inbox = client.fetch_inbox(&mut alice).await.unwrap();
    assert!(!primary_inbox.iter().any(|event| matches!(
        event,
        InboundEvent::CallAnswerClaimedV2 {
            call_instance_id,
            ..
        } if call_instance_id == &linked_call
    )));

    let winner = client
        .prepare_call_winner_v2_to_mailbox(
            &mut alice2,
            &bob_key,
            &bob_reply,
            &linked_call,
            &linked_offer,
            &linked_claim,
            "0",
            expires_at,
        )
        .unwrap();
    client.post_envelope(&winner).await.unwrap();
    let bob_inbox = client.fetch_inbox(&mut bob).await.unwrap();
    assert!(bob_inbox.iter().any(|event| matches!(
        event,
        InboundEvent::CallWinnerV2 {
            call_instance_id,
            claim_nonce,
            winner_device_id,
            ..
        } if call_instance_id == &linked_call
            && claim_nonce == &linked_claim
            && winner_device_id == "0"
    )));

    // A callee-side terminal follows the same authenticated route back to the linked
    // caller, without waking or mutating the caller's primary device.
    let terminal = client
        .prepare_call_terminal_v2_to_mailbox(
            &mut bob,
            &routed_caller.0,
            &routed_caller.1,
            &linked_call,
            &linked_offer,
            client_core::callstate::CallTerminalReason::DeclinedHere,
            "0",
            expires_at,
        )
        .unwrap();
    client.post_envelope(&terminal).await.unwrap();
    let linked_inbox = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    assert!(linked_inbox.iter().any(|event| matches!(
        event,
        InboundEvent::CallTerminalV2 {
            call_instance_id,
            reason: client_core::callstate::CallTerminalReason::DeclinedHere,
            ..
        } if call_instance_id == &linked_call
    )));
    let primary_inbox = client.fetch_inbox(&mut alice).await.unwrap();
    assert!(!primary_inbox.iter().any(|event| matches!(
        event,
        InboundEvent::CallTerminalV2 {
            call_instance_id,
            ..
        } if call_instance_id == &linked_call
    )));
}

#[tokio::test]
async fn group_call_meshes_three_parties_through_blind_pair_rooms() {
    use client_core::call::{AudioIo, CallTicket, SAMPLES_PER_FRAME};
    use client_core::groupcall::{run_group_call, GroupCallEvent, GroupLeg, PeerGains};
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
    let ring_id = signal_id(29);
    let coordinator_key = alice.ratchet_ref().identity_key();
    let coordinator_reply = client.device_mailbox("alice", "0").unwrap();
    let (created_at, ring_expires_at, expires_at) = signal_times();
    let offer_for_bob = client
        .prepare_group_call_offer_v2(
            &mut alice,
            &bob_contact,
            &group.id,
            &instance,
            &ring_id,
            &signal_id(30),
            &t_ab.call_id,
            &t_ab.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            "alice",
            &coordinator_key,
            "0",
            &coordinator_reply,
            false,
        )
        .unwrap();
    let offer_for_carol = client
        .prepare_group_call_offer_v2(
            &mut alice,
            &carol_contact,
            &group.id,
            &instance,
            &ring_id,
            &signal_id(31),
            &t_ac.call_id,
            &t_ac.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            "alice",
            &coordinator_key,
            "0",
            &coordinator_reply,
            false,
        )
        .unwrap();
    let results = client
        .post_envelopes_concurrent(&[offer_for_bob, offer_for_carol])
        .await;
    assert!(results.iter().all(Result::is_ok));

    // Bob and Carol each receive exactly their own leg's capability.
    let take_offer = |inbox: &[InboundEvent]| {
        inbox
            .iter()
            .find_map(|e| match e {
                InboundEvent::GroupCallOfferedV2 {
                    sender_identity_key,
                    call_instance_id,
                    call_id,
                    key_b64,
                    group_id,
                    ..
                } => {
                    assert_eq!(*sender_identity_key, alice.ratchet_ref().identity_key());
                    assert_eq!(*call_instance_id, instance);
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

    // Bob's device must claim the group answer and wait for Alice, the stable
    // coordinator, to name it as winner before it emits or joins any pair leg.
    let bob_claim = signal_id(33);
    let bob_reply = client.device_mailbox("bob", "0").unwrap();
    let claim = client
        .prepare_group_call_answer_claim_v2_to_mailbox(
            &mut bob,
            &coordinator_key,
            &coordinator_reply,
            &group.id,
            &instance,
            &ring_id,
            &bob_claim,
            "0",
            &bob_reply,
            expires_at,
        )
        .unwrap();
    client.post_envelope(&claim).await.unwrap();
    let alice_claims = client.fetch_inbox(&mut alice).await.unwrap();
    assert!(alice_claims.iter().any(|event| matches!(
        event,
        InboundEvent::GroupCallAnswerClaimedV2 {
            call_instance_id,
            ring_id: got_ring,
            claim_nonce,
            answering_device_id,
            ..
        } if call_instance_id == &instance
            && got_ring == &ring_id
            && claim_nonce == &bob_claim
            && answering_device_id == "0"
    )));
    let winner = client
        .prepare_group_call_winner_v2_to_mailbox(
            &mut alice,
            &bob.ratchet_ref().identity_key(),
            &bob_reply,
            &group.id,
            &instance,
            &ring_id,
            &bob_claim,
            "0",
            expires_at,
        )
        .unwrap();
    client.post_envelope(&winner).await.unwrap();
    let bob_winner = client.fetch_inbox(&mut bob).await.unwrap();
    assert!(bob_winner.iter().any(|event| matches!(
        event,
        InboundEvent::GroupCallWinnerV2 {
            call_instance_id,
            ring_id: got_ring,
            claim_nonce,
            winner_device_id,
            ..
        } if call_instance_id == &instance
            && got_ring == &ring_id
            && claim_nonce == &bob_claim
            && winner_device_id == "0"
    )));

    // Only after that winner, Bob offers Carol their direct pair leg.
    let bob_carol_contact = client.add_contact(&mut bob, "carol").await.unwrap();
    let t_bc = CallTicket::mint();
    client
        .send_group_call_offer_v2(
            &mut bob,
            &bob_carol_contact,
            &group.id,
            &instance,
            &ring_id,
            &signal_id(32),
            &t_bc.call_id,
            &t_bc.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            "alice",
            &coordinator_key,
            "0",
            &coordinator_reply,
            false,
        )
        .await
        .unwrap();
    let carol_inbox2 = client.fetch_inbox(&mut carol).await.unwrap();
    let (bc_call_id, bc_key) = carol_inbox2
        .iter()
        .find_map(|e| match e {
            InboundEvent::GroupCallOfferedV2 {
                call_id,
                key_b64,
                call_instance_id,
                ..
            } if *call_instance_id == instance && *call_id != carol_call_id => {
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
                EngineAudio::Sine(s) => {
                    run_group_call(leg_rx, s, stop_rx, m, PeerGains::default(), ev_tx).await
                }
                EngineAudio::Rec(r) => {
                    run_group_call(leg_rx, r, stop_rx, m, PeerGains::default(), ev_tx).await
                }
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
        .send_group_call_terminal_v2(
            &mut bob,
            &bob_carol_contact,
            &group.id,
            &instance,
            &ring_id,
            client_core::callstate::CallTerminalReason::DeclinedHere,
            "0",
            "alice",
            &coordinator_key,
            "0",
            expires_at,
        )
        .await
        .unwrap();
    let carol_inbox3 = client.fetch_inbox(&mut carol).await.unwrap();
    assert!(carol_inbox3.iter().any(|event| matches!(
        event,
        InboundEvent::GroupCallTerminalV2 {
            call_instance_id,
            reason: client_core::callstate::CallTerminalReason::DeclinedHere,
            ..
        } if *call_instance_id == instance
    )));

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
    let call_instance_id = signal_id(40);
    let (created_at, ring_expires_at, expires_at) = signal_times();
    client
        .send_call_offer_v2(
            &mut alice,
            &bob_contact,
            &call_instance_id,
            &signal_id(41),
            &first.call_id,
            &first.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            "",
        )
        .await
        .unwrap();
    // The silent resume of that call: FRESH room id + key, marker names the old call.
    let resumed = client_core::call::CallTicket::mint();
    client
        .send_call_offer_v2(
            &mut alice,
            &bob_contact,
            &call_instance_id,
            &signal_id(42),
            &resumed.call_id,
            &resumed.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            &first.call_id,
        )
        .await
        .unwrap();

    let inbox = client.fetch_inbox(&mut bob).await.unwrap();
    let offers: Vec<(String, String, String, String)> = inbox
        .iter()
        .filter_map(|e| match e {
            InboundEvent::CallOfferedV2 {
                call_instance_id,
                offer_id,
                call_id,
                resume_of,
                ..
            } => Some((
                call_instance_id.clone(),
                offer_id.clone(),
                call_id.clone(),
                resume_of.clone(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(offers.len(), 2);
    assert_eq!(
        offers[0],
        (
            call_instance_id.clone(),
            signal_id(41),
            first.call_id.clone(),
            String::new()
        )
    );
    assert_eq!(
        offers[1],
        (
            call_instance_id,
            signal_id(42),
            resumed.call_id.clone(),
            first.call_id.clone()
        )
    );
    // The resume never reuses the old room or key.
    assert_ne!(resumed.call_id, first.call_id);
    assert_ne!(resumed.key_b64, first.key_b64);
}

/// The scoped call-control identity, end to end through a real relay: a linked Android-
/// shaped device publishes its call key, a peer resolves it **only** through the
/// KT-verified roster, seals a capsule that only that device opens — and a device
/// revoked from the roster loses the shelf entirely.
#[tokio::test]
async fn call_control_keys_publish_and_verify_through_the_kt_roster() {
    use crypto_core::callkey::{seal_capsule, CallKey};

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut alice_hist = History::new();
    let mut bob_hist = History::new();

    // Alice links a phone; that phone is the one that needs a locked-ring identity.
    let (mut phone, _) = create_account_with_username("alice", "Phone-Password-99!").unwrap();
    let req = client.create_link_request(&phone);
    client
        .authorize_link(&alice, &mut alice_hist, &req, "Alice-Password-123!")
        .await
        .unwrap();
    let linked = client
        .complete_link(&mut phone, &req, "Alice-Password-123!")
        .await
        .unwrap();
    let phone_hist = linked.history;
    let phone_mailbox = client.device_mailbox("alice", &req.device_id).unwrap();
    let _ = client.fetch_inbox(&mut alice).await.unwrap();

    // The phone mints a call key and publishes it from its own device mailbox.
    let call_key = CallKey::generate();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    client
        .publish_call_key(&phone, &phone_mailbox, &req.device_id, &call_key, now)
        .await
        .unwrap();

    // Bob cannot trust it before he has KT-verified alice's roster.
    assert!(
        client
            .fetch_verified_call_key(&bob_hist, "alice", &req.device_id)
            .await
            .is_none(),
        "an unpinned roster must yield no call key"
    );
    client
        .warm_account_routes(&mut bob, &mut bob_hist, "alice")
        .await
        .unwrap();
    let binding = client
        .fetch_verified_call_key(&bob_hist, "alice", &req.device_id)
        .await
        .expect("verified against the pinned roster");
    assert_eq!(binding.call_key, call_key.public_b64());

    // A capsule sealed to it opens on the phone and nowhere else.
    let capsule = seal_capsule(&binding.call_key, b"ring: instance+handle").unwrap();
    assert_eq!(
        call_key.open_capsule(&capsule).unwrap(),
        b"ring: instance+handle"
    );
    assert!(CallKey::generate().open_capsule(&capsule).is_none());

    // Bob rings the phone with a real capsule: it reaches the call-control mailbox and
    // the phone verifies it with the call-control key alone — no account, no vault.
    let call_instance_id = signal_id(42);
    let offer_id = signal_id(43);
    let bob_device_id = "0";
    let bob_mailbox = client.device_mailbox("bob", bob_device_id).unwrap();
    let bob_signing_key = bob.ratchet_ref().signing_key();
    let plan = |kind, reason| client_core::callcapsule::CapsulePlan {
        kind,
        call_instance_id: call_instance_id.clone(),
        offer_id: offer_id.clone(),
        from: "bob".into(),
        caller_identity_key: bob.ratchet_ref().identity_key(),
        caller_device_id: bob_device_id.into(),
        to_device_id: req.device_id.clone(),
        video: false,
        group: false,
        display_name: "Bob".into(),
        created_at: now,
        ring_expires_at: now + client_core::callstate::CALL_RING_TIMEOUT_SECS,
        expires_at: now + client_core::callstate::CALL_SIGNAL_TTL_SECS,
        reply_to_mailbox: bob_mailbox.clone(),
        reply_call_mailbox: client_core::call_mailbox_for(
            protocol_types::IdentityHash::from_identifier("bob").as_str(),
            bob_device_id,
        )
        .unwrap(),
        reply_call_key: "bob-call-key".into(),
        signer: client_core::callcapsule::CapsuleSigner::Roster,
        reason,
    };
    let sent = client
        .send_call_capsule(
            &bob,
            "alice",
            &binding,
            plan(client_core::callcapsule::CapsuleKind::Offer, None),
        )
        .await
        .unwrap();
    // A caller the phone cannot place is refused — that is the locked-device screening
    // gate, and it drains the capsule out of the mailbox all the same.
    //
    // The stats are the point of E-9: "refused" and "the mailbox was empty" produce the
    // same `Vec::new()`, and telling them apart took four rounds of device testing. A
    // drain that fetched one capsule and placed none of its signers is a *screening*
    // outcome, and it has to be distinguishable from a drain that found nothing at all.
    let (refused, stats) = client
        .drain_verified_capsules(&call_key, "alice", &req.device_id, now, |_| None)
        .await
        .unwrap();
    assert!(refused.is_empty());
    assert_eq!(stats.fetched, 1, "the capsule was there to be taken");
    assert_eq!(
        stats.decoded, 1,
        "and it decoded — this is not a codec fault"
    );
    assert_eq!(
        stats.refused_unplaceable, 1,
        "the signer could not be placed"
    );
    assert_eq!(stats.refused_signature, 0);
    assert_eq!(stats.accepted(), 0);
    assert!(
        stats.dropped_everything(),
        "took capsules and kept none: the shape that raises a ring with no state behind it"
    );

    // Same capsule, this time from a caller we can place: it rings, carrying the logical
    // call id the encrypted offer uses and no media capability at all.
    let approved = |capsule: &client_core::callcapsule::CallCapsule| {
        (capsule.from == "bob" && capsule.caller_device_id == bob_device_id)
            .then(|| bob_signing_key.clone())
    };
    client
        .send_call_capsule(
            &bob,
            "alice",
            &binding,
            plan(client_core::callcapsule::CapsuleKind::Offer, None),
        )
        .await
        .unwrap();
    let (rings, stats) = client
        .drain_verified_capsules(&call_key, "alice", &req.device_id, now, approved)
        .await
        .unwrap();
    assert_eq!(stats.accepted(), 1, "placed, verified, and kept");
    assert!(!stats.dropped_everything());
    assert_eq!(rings.len(), 1);
    assert_eq!(rings[0].call_instance_id, call_instance_id);
    assert_eq!(
        rings[0].offer_id, offer_id,
        "the capsule names the record the encrypted offer will key"
    );
    assert_eq!(rings[0].reply_to_mailbox, bob_mailbox);
    assert_ne!(rings[0].ring_handle, sent.ring_handle, "per-capsule handle");
    // Acked: a second drain finds nothing, so a capsule cannot ring twice. `fetched: 0` is
    // what makes this an empty mailbox rather than a refusal — the distinction E-9 adds.
    let (again, stats) = client
        .drain_verified_capsules(&call_key, "alice", &req.device_id, now, approved)
        .await
        .unwrap();
    assert!(again.is_empty());
    assert_eq!(stats.fetched, 0, "empty mailbox, not a refused capsule");
    assert!(!stats.dropped_everything());

    // The cancellation travels the same way, as a terminal capsule with an honest reason.
    client
        .send_call_capsule(
            &bob,
            "alice",
            &binding,
            plan(
                client_core::callcapsule::CapsuleKind::Terminal,
                Some(client_core::callstate::CallTerminalReason::CallerCancelled),
            ),
        )
        .await
        .unwrap();
    let (terminals, _) = client
        .drain_verified_capsules(&call_key, "alice", &req.device_id, now, approved)
        .await
        .unwrap();
    assert_eq!(terminals.len(), 1);
    assert_eq!(
        terminals[0].reason,
        Some(client_core::callstate::CallTerminalReason::CallerCancelled)
    );
    assert_eq!(terminals[0].call_instance_id, call_instance_id);
    // Another device's call key cannot authenticate to this mailbox.
    assert!(matches!(
        client
            .drain_call_mailbox(&CallKey::generate(), "alice", &req.device_id)
            .await,
        Err(client_core::ClientError::AuthRejected)
    ));

    // The locked-vault path: with the chat vault sealed there is no account to derive the
    // mailbox from, only the account hash the call-control store carries. Addressing by
    // hash must reach the same mailbox — and a capsule verified against the approved-caller
    // screening index (what a locked device screens with) still lands.
    let store_key = *crypto_core::callkey::call_store_key(&[3u8; crypto_core::DEVICE_KEY_LEN]);
    let mut screen_index = client_core::callscreen::ScreenIndex::default();
    screen_index
        .entries
        .push(client_core::callscreen::ScreenEntry {
            caller: crypto_core::callkey::screen_hash(&store_key, "bob"),
            devices: vec![(bob_device_id.to_string(), bob_signing_key.clone())],
        });
    let sealed_index = screen_index.seal(&store_key);
    let reopened = client_core::callscreen::ScreenIndex::open(&store_key, &sealed_index).unwrap();
    client
        .send_call_capsule(
            &bob,
            "alice",
            &binding,
            plan(
                client_core::callcapsule::CapsuleKind::Terminal,
                Some(client_core::callstate::CallTerminalReason::CallerCancelled),
            ),
        )
        .await
        .unwrap();
    let alice_hash = client_core::identity_hash_for("alice");
    let (locked, _) = client
        .drain_verified_capsules_by_hash(
            &call_key,
            &alice_hash,
            &req.device_id,
            now,
            |capsule: &client_core::callcapsule::CallCapsule| {
                reopened.signing_key(&store_key, &capsule.from, &capsule.caller_device_id)
            },
        )
        .await
        .unwrap();
    assert_eq!(locked.len(), 1, "a locked device drains its own mailbox");
    assert_eq!(locked[0].call_instance_id, call_instance_id);
    assert_eq!(
        locked[0].reason,
        Some(client_core::callstate::CallTerminalReason::CallerCancelled),
        "the cancellation that must stop a locked phone ringing"
    );

    // ── The reply direction: a decline sent with the vault still locked (§3.4). ──
    // The phone has no roster key — it is in the vault — so it signs with its
    // call-control key, and it addresses the caller using only what the offer capsule
    // carried. Nothing here consults the relay for a key.
    let bob_call_key = CallKey::generate();
    let bob_binding = client
        .publish_call_key(&bob, &bob_mailbox, bob_device_id, &bob_call_key, now)
        .await
        .unwrap();
    let decline = client_core::callcapsule::CallCapsule::new(
        client_core::callcapsule::CapsulePlan {
            kind: client_core::callcapsule::CapsuleKind::Terminal,
            call_instance_id: call_instance_id.clone(),
            offer_id: offer_id.clone(),
            from: "alice".into(),
            caller_identity_key: String::new(),
            caller_device_id: req.device_id.clone(),
            to_device_id: bob_device_id.into(),
            video: false,
            group: false,
            display_name: String::new(),
            created_at: now,
            ring_expires_at: now + client_core::callstate::CALL_SIGNAL_TTL_SECS,
            expires_at: now + client_core::callstate::CALL_SIGNAL_TTL_SECS,
            reply_to_mailbox: client_core::call_mailbox_for(&alice_hash, &req.device_id).unwrap(),
            reply_call_mailbox: client_core::call_mailbox_for(&alice_hash, &req.device_id).unwrap(),
            reply_call_key: call_key.public_b64(),
            signer: client_core::callcapsule::CapsuleSigner::CallKey,
            reason: Some(client_core::callstate::CallTerminalReason::DeclinedHere),
        },
        |payload| call_key.sign(payload),
    );
    let bob_call_mailbox = client_core::call_mailbox_for(
        protocol_types::IdentityHash::from_identifier("bob").as_str(),
        bob_device_id,
    )
    .unwrap();
    client
        .post_call_capsule_to(
            &bob_call_mailbox,
            &bob_binding.call_key,
            &decline.encode(),
            now + client_core::callstate::CALL_SIGNAL_TTL_SECS,
        )
        .await
        .unwrap();
    // The caller verifies it against the call-control key alice's KT-verified binding
    // publishes — the same root of trust as her roster key, with a narrower reach.
    let alice_binding = client
        .fetch_verified_call_key(&History::new(), "alice", &req.device_id)
        .await;
    assert!(
        alice_binding.is_none(),
        "no pinned roster ⇒ no trusted call key, even for a real binding"
    );
    let (declines, _) = client
        .drain_verified_capsules_by_hash(
            &bob_call_key,
            protocol_types::IdentityHash::from_identifier("bob").as_str(),
            bob_device_id,
            now,
            |capsule: &client_core::callcapsule::CallCapsule| {
                (capsule.signer == client_core::callcapsule::CapsuleSigner::CallKey
                    && capsule.from == "alice"
                    && capsule.caller_device_id == req.device_id)
                    .then(|| binding.call_signing_key.clone())
            },
        )
        .await
        .unwrap();
    assert_eq!(declines.len(), 1, "a locked phone can still refuse a call");
    assert_eq!(
        declines[0].reason,
        Some(client_core::callstate::CallTerminalReason::DeclinedHere)
    );

    // A replayed OLDER publication cannot displace the live key.
    let stale = CallKey::generate();
    let replayed = client
        .publish_call_key(&phone, &phone_mailbox, &req.device_id, &stale, now - 1)
        .await;
    assert!(replayed.is_err(), "an older call key must not be accepted");
    assert_eq!(
        client
            .fetch_verified_call_key(&bob_hist, "alice", &req.device_id)
            .await
            .unwrap()
            .call_key,
        call_key.public_b64()
    );

    // Alice revokes the phone: its call-control shelf goes with its roster entry.
    client
        .revoke_device(&alice, &mut alice_hist, &req.device_id)
        .await
        .unwrap();
    client
        .warm_account_routes(&mut bob, &mut bob_hist, "alice")
        .await
        .unwrap();
    assert!(
        client
            .fetch_verified_call_key(&bob_hist, "alice", &req.device_id)
            .await
            .is_none(),
        "a revoked device must have no verifiable call key"
    );
    // …and its call-control mailbox stops authenticating, so a revoked device cannot
    // keep collecting capsules.
    assert!(matches!(
        client
            .drain_call_mailbox(&call_key, "alice", &req.device_id)
            .await,
        Err(client_core::ClientError::DeviceRevoked)
    ));
    drop(phone_hist);
}

/// **The original bug, end to end.** The caller answers on one device before the other
/// device's offer has even been posted, so the linked device drains its mailbox and finds
/// the terminal control FIRST and the offer SECOND. Nothing in the transport preserves
/// order here — the two envelopes are posted independently, and a phone woken by a push
/// drains whatever is queued — so the ordering must be handled where the state lives.
///
/// The in-memory permutation tests cover this exhaustively; this one proves the whole
/// path: real ratchet sessions, a real relay, real mailboxes, decoded events fed to the
/// registry in the order the device actually received them.
#[tokio::test]
async fn a_terminal_that_overtakes_its_offer_never_rings_the_late_device() {
    use client_core::callstate::{CallRegistry, CallTerminalReason, OfferDecision};

    let (base, ws, _state) = spawn_relay().await;
    let pinned = Client::fetch_kt_pubkey(&base, None).await.unwrap();
    let client = Client::new(&base, &ws, &pinned);

    let (mut alice, _) = create_account_with_username("alice", "Alice-Password-123!").unwrap();
    let (mut bob, _) = create_account_with_username("bob", "Bob-Password-456!").unwrap();
    client.register(&mut alice, 5).await.unwrap();
    client.register(&mut bob, 5).await.unwrap();
    let mut alice_hist = History::new();
    let mut bob_hist = History::new();

    let (mut alice2, _) = create_account_with_username("alice", "Device2-Password-99!").unwrap();
    let req = client.create_link_request(&alice2);
    client
        .authorize_link(&alice, &mut alice_hist, &req, "Alice-Password-123!")
        .await
        .unwrap();
    client
        .complete_link(&mut alice2, &req, "Alice-Password-123!")
        .await
        .unwrap();
    let alice2_mailbox = client.device_mailbox("alice", &req.device_id).unwrap();
    let _ = client.fetch_inbox(&mut alice).await.unwrap();

    let alice_contact = client.add_contact(&mut bob, "alice").await.unwrap();
    client
        .warm_account_routes(&mut bob, &mut bob_hist, "alice")
        .await
        .unwrap();

    let ticket = client_core::call::CallTicket::mint();
    let call_instance_id = signal_id(0x40);
    let offer_id = signal_id(0x41);
    let (created_at, ring_expires_at, expires_at) = signal_times();

    // The linked device's offer is prepared but deliberately NOT posted yet: this is the
    // window the old sequential fan left open, where the primary could answer first.
    let late_offer = client
        .extra_call_offer_envelopes_v2(
            &mut bob,
            &bob_hist,
            &alice_contact,
            &call_instance_id,
            &offer_id,
            &ticket.call_id,
            &ticket.key_b64,
            created_at,
            ring_expires_at,
            expires_at,
            "0",
            "",
        )
        .unwrap();
    assert_eq!(late_offer.len(), 1, "one copy for the linked device");

    // The primary answered elsewhere, so the caller cancels every other device first.
    let terminal = client
        .extra_call_terminal_envelopes_v2(
            &mut bob,
            &bob_hist,
            &alice_contact,
            &call_instance_id,
            &offer_id,
            CallTerminalReason::AnsweredElsewhere,
            "0",
            expires_at,
        )
        .unwrap();
    for envelope in &terminal {
        client.post_envelope(envelope).await.unwrap();
    }
    for envelope in &late_offer {
        client.post_envelope(envelope).await.unwrap();
    }

    // What the linked device actually drains, in order.
    let inbox = client
        .fetch_inbox_as(&mut alice2, &alice2_mailbox)
        .await
        .unwrap();
    let call_events: Vec<&InboundEvent> = inbox
        .iter()
        .filter(|event| {
            matches!(
                event,
                InboundEvent::CallOfferedV2 { .. } | InboundEvent::CallTerminalV2 { .. }
            )
        })
        .collect();
    assert!(
        matches!(
            call_events.first(),
            Some(InboundEvent::CallTerminalV2 { .. })
        ),
        "the terminal must arrive first for this test to prove anything"
    );
    assert!(matches!(
        call_events.get(1),
        Some(InboundEvent::CallOfferedV2 { .. })
    ));

    // Apply them in exactly that order, as the shell's signal handler does.
    let mut registry = CallRegistry::default();
    let now = created_at;
    for event in call_events {
        match event {
            InboundEvent::CallTerminalV2 {
                call_instance_id,
                offer_id,
                reason,
                ..
            } => {
                registry.record_terminal(call_instance_id, offer_id, *reason, now, 0);
            }
            InboundEvent::CallOfferedV2 {
                call_instance_id,
                offer_id,
                created_at,
                ring_expires_at,
                ..
            } => {
                // The tombstone is what makes the late offer silent. Before this work it
                // rang for the full 45 s on a call that was already over.
                assert_eq!(
                    registry.receive_offer(
                        call_instance_id,
                        offer_id,
                        *created_at,
                        *ring_expires_at,
                        now,
                        0
                    ),
                    OfferDecision::Suppressed(CallTerminalReason::AnsweredElsewhere),
                );
            }
            _ => unreachable!("filtered above"),
        }
    }
}
