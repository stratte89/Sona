package app.sona.messenger

import android.net.Uri
import android.telecom.DisconnectCause
import androidx.core.telecom.CallAttributesCompat
import androidx.core.telecom.CallControlScope
import androidx.core.telecom.CallEndpointCompat
import androidx.core.telecom.CallsManager
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

/// SONA-TELECOM — Core-Telecom (`androidx.core:core-telecom`) is the single authority for
/// this app's call lifecycle and audio route.
///
/// Why it exists (internal/CALL_PLAN.md §7): the ring used to be a hand-built `CallStyle`
/// notification plus a `MediaSession`, with the real state in Rust memory. That is two
/// state machines, no headset/watch/car integration, and no way for the system to know a
/// call is up. Telecom owns ringing / answered / active / held / disconnected; Rust owns
/// the protocol and drives Telecom through the entry points below; the notification
/// remains presentation only.
///
/// Threading contract: every platform callback here does the smallest possible thing —
/// hand the event to Rust and return. Nothing waits for a network round trip or for a
/// human to unlock the phone inside a Telecom callback (§8): Rust answers back through
/// `setActive` / `disconnect` when it is ready.
///
/// Lifetime: calls are added on an application-scoped coroutine scope, not an Activity's,
/// so a destroyed Activity or WebView cannot take the call down with it.
object TelecomBridge {
  /// Telecom → Rust. One JSON object: `{"ring":…,"event":…}` plus event-specific fields.
  @JvmStatic external fun nativeTelecomEvent(json: String)

  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
  private val jobs = ConcurrentHashMap<String, Job>()
  private val controls = ConcurrentHashMap<String, CallControlScope>()

  @Volatile private var manager: CallsManager? = null
  @Volatile private var registered = false

  private fun manager(): CallsManager? {
    manager?.let { return it }
    return try {
      CallsManager(SonaApp.instance).also { manager = it }
    } catch (t: Throwable) {
      null
    }
  }

  /// Register with Telecom once per process. Baseline capabilities plus video; hold and
  /// streaming are deliberately NOT advertised — Sona does not implement their full state
  /// semantics, and advertising a capability it cannot honor is how a car head unit ends
  /// up holding a call that never comes back (§7.5).
  @JvmStatic
  fun register(): Boolean {
    if (registered) return true
    val manager = manager() ?: return false
    return try {
      manager.registerAppWithTelecom(
        CallsManager.CAPABILITY_BASELINE or CallsManager.CAPABILITY_SUPPORTS_VIDEO_CALLING
      )
      registered = true
      true
    } catch (t: Throwable) {
      false
    }
  }

  /// Put an incoming call in front of the system: this is what rings, on the phone and on
  /// every surface Telecom reaches (watch, headset, car). `ringId` is the id Rust
  /// correlates with — the capsule's ring handle, or the media call id.
  @JvmStatic
  fun addIncoming(ringId: String, displayName: String, video: Boolean): Boolean =
    addCall(ringId, displayName, video, CallAttributesCompat.DIRECTION_INCOMING)

  /// The outgoing half: the system knows a call is being placed, so audio focus, routing,
  /// and other-call interaction behave like any other telephony app.
  @JvmStatic
  fun addOutgoing(ringId: String, displayName: String, video: Boolean): Boolean =
    addCall(ringId, displayName, video, CallAttributesCompat.DIRECTION_OUTGOING)

  private fun addCall(
    ringId: String,
    displayName: String,
    video: Boolean,
    direction: Int,
  ): Boolean {
    if (!register()) return false
    val manager = manager() ?: return false
    if (jobs.containsKey(ringId)) return true // idempotent: one Telecom call per ring
    val attributes = CallAttributesCompat(
      displayName = displayName.ifEmpty { "Sona" },
      // Sona has no dialable address; the scheme carries the ring id so the platform's
      // own logs never contain a username. Nothing routes on it.
      address = Uri.fromParts("sona", ringId, null),
      direction = direction,
      callType =
        if (video) CallAttributesCompat.CALL_TYPE_VIDEO_CALL
        else CallAttributesCompat.CALL_TYPE_AUDIO_CALL,
      callCapabilities = CallAttributesCompat.SUPPORTS_SET_INACTIVE,
    )
    // Registered lazily by the coroutine itself, so a failure that reaches `finally`
    // before this function returns cannot be undone by a later write: `forget` would run
    // first and the map would keep a dead job, which the idempotence check above then
    // reads as "already added" and returns true for a call that never rang.
    val job = scope.launch(start = kotlinx.coroutines.CoroutineStart.LAZY) {
      try {
        manager.addCall(
          attributes,
          onAnswer = { callType ->
            // Report and return. Rust decides whether this device may answer (unlock
            // gating, the caller's winner acknowledgement) and calls back.
            event(ringId, "answer") { it.put("video", callType == CallAttributesCompat.CALL_TYPE_VIDEO_CALL) }
          },
          onDisconnect = { cause ->
            event(ringId, "disconnect") { it.put("cause", cause.code) }
            forget(ringId)
          },
          onSetActive = { event(ringId, "active") },
          onSetInactive = { event(ringId, "inactive") },
        ) {
          controls[ringId] = this
          event(ringId, "added")
          launch {
            currentCallEndpoint.collect { endpoint ->
              val route = routeName(endpoint)
              lastRoute[ringId] = route
              // MediaBridge keeps capture/playout but no longer decides the route; this
              // is how it learns what Telecom chose (internal/CALL_PLAN.md §7.4).
              try { MediaBridge.onTelecomRoute(route) } catch (_: Throwable) {}
              event(ringId, "endpoint") {
                it.put("route", route)
                it.put("name", endpoint.name.toString())
              }
            }
          }
          launch {
            availableEndpoints.collect { endpoints ->
              // Kept so a route request can name an endpoint object: Telecom takes the
              // endpoint, not a string, and the list only arrives as a flow.
              lastEndpoints[ringId] = endpoints
              val routes = JSONArray()
              endpoints.forEach { routes.put(routeName(it)) }
              event(ringId, "endpoints") { it.put("routes", routes) }
            }
          }
          launch { isMuted.collect { muted -> event(ringId, "muted") { it.put("muted", muted) } } }
        }
      } catch (t: Throwable) {
        // Telecom refused the call (another call owns the slot, a permission is missing,
        // the platform is out of resources). Fail loudly rather than leaving a call the
        // system does not know about. `op = add` is what makes this terminal on the Rust
        // side: a call the system never accepted is not a call.
        event(ringId, "error") {
          it.put("op", "add")
          it.put("reason", t.javaClass.simpleName)
        }
      } finally {
        forget(ringId)
      }
    }
    jobs[ringId] = job
    job.start()
    return true
  }

  /// Rust accepted the platform's answer action: tell Telecom this call is connecting,
  /// then active once media is up (`setActive`).
  @JvmStatic
  fun answer(ringId: String, video: Boolean) = control(ringId, "answer") {
    answer(
      if (video) CallAttributesCompat.CALL_TYPE_VIDEO_CALL
      else CallAttributesCompat.CALL_TYPE_AUDIO_CALL
    )
  }

  /// Media is flowing.
  @JvmStatic fun setActive(ringId: String) = control(ringId, "active") { setActive() }

  /// Held / interrupted by another call.
  @JvmStatic fun setInactive(ringId: String) = control(ringId, "inactive") { setInactive() }

  /// End the call in the system. `cause` uses `android.telecom.DisconnectCause` codes:
  /// LOCAL (2) for our own hangup, REMOTE (3) for the peer's, REJECTED (6) for a decline,
  /// MISSED (5) for an unanswered ring, ERROR (1) for a transport failure.
  ///
  /// The bookkeeping is dropped **after** the disconnect completes, never beside it:
  /// `forget` cancels the coroutine that owns this call's session, and cancelling it while
  /// the disconnect is still in flight races the platform into seeing the session die
  /// instead of the cause we chose. The system call log is user-visible, so which cause
  /// arrives is not a detail — and on the losing side of that race the call can be left
  /// standing altogether.
  @JvmStatic
  fun disconnect(ringId: String, cause: Int) {
    val scopeForCall = controls[ringId]
    if (scopeForCall == null) {
      // Two different situations, and only one of them is safe to `forget`. If the call is
      // still being added — a cancellation that arrives within milliseconds of the offer —
      // cancelling that coroutine is the A-7 failure in a different window: the platform
      // sees the session die instead of the cause we chose. Let the add finish; its own
      // `finally` cleans up, and the disconnect below reaches the session once it exists.
      val adding = jobs[ringId]?.isActive == true
      if (adding) {
        scope.launch {
          // Give the session a moment to appear, then disconnect it properly.
          repeat(20) {
            controls[ringId]?.let { live ->
              try {
                live.disconnect(DisconnectCause(cause))
              } catch (t: Throwable) {
                event(ringId, "error") {
                  it.put("op", "disconnect")
                  it.put("reason", t.javaClass.simpleName)
                }
              }
              forget(ringId)
              return@launch
            }
            kotlinx.coroutines.delay(50)
          }
          forget(ringId) // it never came up; nothing to disconnect
        }
        return
      }
      forget(ringId) // no live session and nothing in flight to wait for
      return
    }
    scope.launch {
      try {
        scopeForCall.disconnect(DisconnectCause(cause))
      } catch (t: Throwable) {
        event(ringId, "error") {
          it.put("op", "disconnect")
          it.put("reason", t.javaClass.simpleName)
        }
      } finally {
        forget(ringId)
      }
    }
  }

  /// Ask Telecom for a different audio route ("earpiece" | "speaker" | "bluetooth" |
  /// "wired"). Telecom owns the decision; the result arrives back as an `endpoint` event,
  /// so a refused request reports the real route rather than the wish.
  @JvmStatic
  fun requestRoute(ringId: String, route: String) = control(ringId, "route") {
    val wanted = lastEndpoints[ringId]?.firstOrNull { routeName(it) == route }
    if (wanted != null) {
      requestEndpointChange(wanted)
    } else {
      // Telecom is not offering that endpoint (a Bluetooth device that went away between
      // the tap and the request, most often). Saying nothing leaves the button showing a
      // route the call is not on; re-publishing the live one is the honest answer, and the
      // same one a refused request gets.
      event(ringId, "endpoint") {
        it.put("route", lastRoute[ringId] ?: "unknown")
        it.put("name", "")
      }
    }
  }

  /// The ring ids Telecom currently holds for this process — what a restarted process
  /// reconciles its stored rings against (§6.4).
  @JvmStatic
  fun activeCalls(): String {
    val out = JSONArray()
    controls.keys.forEach { out.put(it) }
    return out.toString()
  }

  @JvmStatic fun isRegistered(): Boolean = registered

  // ── internals ──

  /// Run one control on the call's scope, reporting which control failed if it does.
  ///
  /// `op` matters: Rust decides from it whether a failure is terminal. A route request
  /// Telecom refuses — a Bluetooth endpoint that vanished mid-call, say — is not a call
  /// that failed, and hanging the call up because the speaker button did not take is the
  /// wrong answer to it (internal/CALL_PLAN.md §7.4: Telecom decides the route, and we report what
  /// it actually did).
  private fun control(ringId: String, op: String, block: suspend CallControlScope.() -> Unit) {
    val scopeForCall = controls[ringId]
    if (scopeForCall == null) {
      // No session for this ring: the platform never accepted the call, or it is already
      // gone. Reporting it matters most for `answer` — Rust would otherwise go on to claim
      // and start media for a call the system does not have, with no audio focus and no
      // route. Silence here is what made that invisible.
      event(ringId, "error") {
        it.put("op", op)
        it.put("reason", "NoCallSession")
      }
      return
    }
    scope.launch {
      try {
        scopeForCall.block()
      } catch (t: Throwable) {
        event(ringId, "error") {
          it.put("op", op)
          it.put("reason", t.javaClass.simpleName)
        }
      }
    }
  }

  /// The endpoints Telecom last offered per ring, from the `availableEndpoints` flow.
  private val lastEndpoints = ConcurrentHashMap<String, List<CallEndpointCompat>>()

  /// The route Telecom last named for each ring, so a request it cannot honor can still
  /// report the truth instead of leaving the button on a route the call is not using.
  private val lastRoute = ConcurrentHashMap<String, String>()

  private fun routeName(endpoint: CallEndpointCompat): String = when (endpoint.type) {
    CallEndpointCompat.TYPE_EARPIECE -> "earpiece"
    CallEndpointCompat.TYPE_SPEAKER -> "speaker"
    CallEndpointCompat.TYPE_BLUETOOTH -> "bluetooth"
    CallEndpointCompat.TYPE_WIRED_HEADSET -> "wired"
    CallEndpointCompat.TYPE_STREAMING -> "streaming"
    else -> "unknown"
  }

  private fun forget(ringId: String) {
    controls.remove(ringId)
    lastEndpoints.remove(ringId)
    lastRoute.remove(ringId)
    jobs.remove(ringId)?.cancel()
  }

  private fun event(ringId: String, kind: String, fill: ((JSONObject) -> Unit)? = null) {
    val json = JSONObject()
    json.put("ring", ringId)
    json.put("event", kind)
    fill?.invoke(json)
    try {
      nativeTelecomEvent(json.toString())
    } catch (_: Throwable) {
      // The native library is not loaded (or the process is going down): the call is
      // still the platform's, and the next process reconciles it from the store.
    }
  }
}
