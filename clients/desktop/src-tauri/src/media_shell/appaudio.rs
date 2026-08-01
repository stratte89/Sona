//! Asking the sound server which sink our own audio goes into.
//!
//! The screen-share echo canceller needs the monitor of the sink the *call* plays into.
//! Picking that by name — the default sink, or the pinned output device — is a guess, and
//! when the guess is wrong the canceller is handed a reference for one signal and asked to
//! find it in another. From inside, that is indistinguishable from an echo that simply is
//! not there, and a field log showed exactly that: a capture that demonstrably carried the
//! far end's voice (they could hear themselves in it) correlating with our playout at the
//! level of two unrelated signals.
//!
//! There is no need to guess. PulseAudio knows which sink every stream is attached to, so
//! this asks it about ours and monitors that sink. Windows never had the problem because
//! its loopback capture is opened *on* the output device, so the two cannot disagree.
//!
//! The [`pulseaudio`] crate is a pure-Rust protocol implementation, already in the tree as
//! cpal's Pulse host. Its high-level client cannot enumerate sink inputs, so the socket,
//! the handshake and the one command are done here directly. Every failure returns `None`
//! and the caller falls back to picking a monitor by name, which is what it did before.

use std::ffi::CString;
use std::io::BufReader;
use std::os::unix::net::UnixStream;

use pulseaudio::protocol;

/// Bound on any single exchange. A command whose reply never comes must fail rather than
/// park the caller's thread — the share falls back to picking a monitor by name, which is
/// a working share, and hanging is not.
const SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// One application's audio stream on the sound server.
pub struct SinkInput {
    pub index: u32,
    /// The sink it plays into — the record stream still connects to that sink's monitor,
    /// `direct_on_input` just narrows what it hears.
    pub sink: u32,
    pub pid: Option<u32>,
    pub app: String,
}

/// A live connection: one writer, and **one** reader for its whole life.
///
/// One reader is not tidiness. A `BufReader` reads ahead, so building a fresh one per
/// exchange lets it swallow bytes belonging to the *next* reply and then drop them — the
/// following read then blocks forever waiting for a message already consumed. That is
/// exactly what happened here, and it looked like the server ignoring us.
struct Conn {
    w: UnixStream,
    r: BufReader<UnixStream>,
    version: u16,
    seq: u32,
}

impl Conn {
    fn open() -> Option<Conn> {
        let path = pulseaudio::socket_path_from_env()?;
        let cookie = pulseaudio::cookie_path_from_env().and_then(|p| std::fs::read(p).ok());
        let w = UnixStream::connect(path).ok()?;
        // Bounded from the very first exchange. A command whose reply never comes must
        // fail rather than park the caller's thread forever — the share falls back to
        // whole-sink capture, which is a working share, and hanging is not.
        w.set_read_timeout(Some(SETUP_TIMEOUT)).ok()?;
        let r = BufReader::new(w.try_clone().ok()?);
        let mut c = Conn {
            w,
            r,
            version: protocol::MAX_VERSION,
            seq: 0,
        };

        let auth: protocol::AuthReply =
            c.roundtrip(protocol::Command::Auth(protocol::AuthParams {
                version: protocol::MAX_VERSION,
                supports_shm: false,
                supports_memfd: false,
                cookie: cookie.unwrap_or_default(),
            }))?;
        c.version = protocol::MAX_VERSION.min(auth.version);

        let mut props = protocol::Props::new();
        props.set(
            protocol::Prop::ApplicationName,
            CString::new("Sona").ok()?.as_c_str(),
        );
        let _: protocol::SetClientNameReply =
            c.roundtrip(protocol::Command::SetClientName(props))?;
        Some(c)
    }

    fn roundtrip<T: protocol::CommandReply>(&mut self, cmd: protocol::Command) -> Option<T> {
        let seq = self.seq;
        self.seq += 1;
        let tag = cmd.tag();
        protocol::write_command_message(&mut self.w, seq, &cmd, self.version).ok()?;
        match protocol::read_reply_message::<T>(&mut self.r, self.version) {
            Ok((_, reply)) => Some(reply),
            Err(e) => {
                crate::diag!("[media] app-audio: {tag:?} got no usable reply ({e})");
                None
            }
        }
    }
}

/// Every application currently playing audio.
pub fn sink_inputs() -> Vec<SinkInput> {
    let Some(mut c) = Conn::open() else {
        return Vec::new();
    };
    let Some(list) =
        c.roundtrip::<protocol::SinkInputInfoList>(protocol::Command::GetSinkInputInfoList)
    else {
        return Vec::new();
    };
    list.iter()
        .map(|i| SinkInput {
            index: i.index,
            sink: i.sink_index,
            pid: prop_u32_of(&i.props, protocol::Prop::ApplicationProcessId),
            app: prop_str_of(&i.props, protocol::Prop::ApplicationName),
        })
        .collect()
}

fn prop_str_of(props: &protocol::Props, key: protocol::Prop) -> String {
    props
        .get(key)
        .and_then(|v| std::str::from_utf8(v).ok())
        .map(|s| s.trim_end_matches('\0').to_string())
        .unwrap_or_default()
}

fn prop_u32_of(props: &protocol::Props, key: protocol::Prop) -> Option<u32> {
    prop_str_of(props, key).parse().ok()
}

/// The sink our own playout is attached to, and the name of that sink's monitor source.
///
/// Matched by process id: our playout stream belongs to this process, so among everything
/// the server is playing, ours is the one whose `application.process.id` is ours.
pub fn our_monitor_source() -> Option<String> {
    let me = std::process::id();
    let mut c = Conn::open()?;
    let list =
        c.roundtrip::<protocol::SinkInputInfoList>(protocol::Command::GetSinkInputInfoList)?;

    // Match on more than the process id.
    //
    // The first version matched only `application.process.id` and quietly found nothing,
    // so the whole mechanism no-oped and the old guess was used without saying so. On this
    // desktop the call plays through cpal's ALSA host as the device literally named
    // "default", which reaches the server through the ALSA-to-PulseAudio plugin — and what
    // that plugin puts in the stream's properties is its business, not ours. The binary
    // name and the application name are two more ways to recognise our own audio, and if
    // none of them match, the list is printed rather than silently abandoned.
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()));
    let mine = |i: &protocol::SinkInputInfo| {
        if prop_u32_of(&i.props, protocol::Prop::ApplicationProcessId) == Some(me) {
            return true;
        }
        let binary = prop_str_of(&i.props, protocol::Prop::ApplicationProcessBinary);
        if let Some(exe) = exe.as_deref() {
            if !binary.is_empty() && binary == exe {
                return true;
            }
        }
        prop_str_of(&i.props, protocol::Prop::ApplicationName)
            .to_ascii_lowercase()
            .contains("sona")
    };

    let Some(sink) = list.iter().find(|i| mine(i)).map(|i| i.sink_index) else {
        crate::diag!(
            "[media] share-audio: none of the {} playing streams look like ours (pid {me},              exe {:?}) — falling back to picking a monitor by name",
            list.len(),
            exe
        );
        for i in list.iter() {
            crate::diag!(
                "[media]   stream #{} on sink {}: pid {:?} binary {:?} name {:?}",
                i.index,
                i.sink_index,
                prop_u32_of(&i.props, protocol::Prop::ApplicationProcessId),
                prop_str_of(&i.props, protocol::Prop::ApplicationProcessBinary),
                prop_str_of(&i.props, protocol::Prop::ApplicationName),
            );
        }
        return None;
    };
    let info: protocol::SinkInfo =
        c.roundtrip(protocol::Command::GetSinkInfo(protocol::GetSinkInfo {
            index: Some(sink),
            name: None,
        }))?;
    info.monitor_source_name.and_then(|n| n.into_string().ok())
}

#[cfg(test)]
mod tests;
