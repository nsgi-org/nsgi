//! # NSGI: Native Web Server Gateway Interface
//!
//! This crate provides the C ABI types and function pointer signatures that form the NSGI protocol.
//! It is `#![no_std]` and has zero dependencies.
//!
//! NSGI is a language-agnostic gateway interface protocol that connects any C ABI host with
//! application logic written in any language supporting FFI.
//!
//! ## Field validity
//!
//! Every field carrying HTTP message text is free of the bytes that delimit an HTTP/1.1 message: no
//! NUL, LF or CR at any position, and no leading or trailing SP or HTAB. Whatever carries a field
//! states how a host handles one breaking this rule.
//!
//! ## Pointer validity
//!
//! A pointer is non-null unless its own documentation says otherwise.
//!
//! ## Status values
//!
//! A callback returns one of the statuses its own documentation names. Zero and positive values
//! report outcomes that are not failures; negative values report errors, and a negative value no
//! status list enumerates is reserved.
//!
//! ## Callback safety
//!
//! Unwinding across a callback boundary is Undefined Behavior; an implementation catches its own
//! panics or builds with `panic = "abort"`. Calls for different requests or connections may run
//! concurrently on any thread, so an implementation is reentrant and does not rely on
//! unsynchronized mutable state.
//!
//! ## Call ordering
//!
//! Calls to one callback for the same request or response are never concurrent with each other,
//! whichever thread makes them, and are ordered so that state the application wrote during one call
//! is visible within the next.

#![no_std]

use core::ffi::c_void;

/// A scheme the host does not report.
pub const NSGI_SCHEME_UNKNOWN: u8 = 0;
/// A plaintext `http` hop the host terminated.
pub const NSGI_SCHEME_HTTP: u8 = 1;
/// A TLS `https` hop the host terminated.
pub const NSGI_SCHEME_HTTPS: u8 = 2;
/// A scheme the host terminated but cannot represent here. A host reporting this supplies
/// [`NsgiRequest::get_var`] and answers `request.scheme`.
pub const NSGI_SCHEME_OTHER: u8 = 3;

/// An address the host cannot represent here, though the connection exists.
pub const NSGI_AF_UNSPEC: u8 = 0;
/// An IPv4 address, carried in the first 4 bytes of [`NsgiAddr::octets`].
pub const NSGI_AF_INET: u8 = 1;
/// An IPv6 address, carried in all 16 bytes of [`NsgiAddr::octets`].
pub const NSGI_AF_INET6: u8 = 2;
/// A UNIX domain socket, named by [`NsgiAddr::path`].
pub const NSGI_AF_UNIX: u8 = 3;

/// A transport address in binary form.
///
/// # Ownership
/// These fields are borrowed from the host, and the application does not free them.
#[repr(C)]
pub struct NsgiAddr {
    /// One of the `NSGI_AF_*` constants.
    pub family: u8,
    /// Port in host byte order; 0 when not applicable. Note that `sockaddr_in::sin_port` is
    /// network byte order.
    pub port: u16,
    /// IPv6 zone index, as carried by `sockaddr_in6::sin6_scope_id`, meaningful only on the node
    /// that produced it. A host reports 0 for an address needing no zone.
    pub scope_id: u32,
    /// Address bytes in network byte order, IPv4 in the first 4; unused bytes are zero. The host
    /// unmaps IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) to [`NSGI_AF_INET`].
    pub octets: [u8; 16],
    /// UNIX socket path bytes. Null unless `family` is [`NSGI_AF_UNIX`]; an unnamed socket has a
    /// `path_len` of 0.
    pub path: *const u8,
    pub path_len: usize,
}

/// A single HTTP header name/value pair.
///
/// # Header names
/// Names are lowercase in both directions: the host folds the names it delivers, and the
/// application supplies folded names. Folding maps bytes `0x41..=0x5A` to `0x61..=0x7A` and leaves
/// every other byte alone; values are unaffected. A host folds any uppercase name it receives
/// before transmitting.
///
/// Beyond case, a name is a token as RFC 9110 defines it: one or more ASCII digits, letters, or
/// bytes among `` !#$%&'*+-.^_`|~ ``. A host treats a name breaking this rule as whatever carries
/// it treats a field breaking the [field validity rule](crate#field-validity).
///
/// # Ownership
/// Received from the host, these fields are borrowed, and the application does not free them.
/// Supplied by the application, they are the application's own; the host never interprets or frees
/// them, and static memory (e.g. `b"content-type"`) is as legal as heap.
#[repr(C)]
pub struct NsgiHeader {
    /// Header name bytes (e.g. `b"content-type"`).
    pub name: *const u8,
    pub name_len: usize,
    /// Header value bytes (e.g. `b"text/plain"`); an empty value has a `value_len` of 0.
    pub value: *const u8,
    pub value_len: usize,
}

/// The [`NsgiRequest::content_length`] of a request that declares no length, such as a chunked
/// request.
pub const NSGI_CONTENT_LENGTH_UNKNOWN: u64 = u64::MAX;

/// [`NsgiGetVar`] found the variable. A zero `*out_value_len` means a known but empty value.
pub const NSGI_VAR_OK: i32 = 0;
/// The host does not recognize the variable.
pub const NSGI_VAR_UNKNOWN: i32 = 1;
/// The lookup failed.
pub const NSGI_VAR_ERROR: i32 = -1;

/// The canonical type signature of the host's variable lookup callback.
///
/// Carries connection and server metadata such as `tls.version`, `tls.cipher`, `server.software`,
/// `proxy_protocol.src_addr`. Names are lowercase ASCII, dot-separated, and compared bytewise.
///
/// `host_ctx` is [`NsgiRequest::host_ctx`] passed back unchanged. On [`NSGI_VAR_OK`] the host
/// writes a pointer and length borrowed for the duration of the `nsgi_handle` call, or, for a call
/// made after that return, until the next `get_var` call for the same request; on any other status
/// the out-parameters are left untouched.
///
/// Returns one of the `NSGI_VAR_*` statuses. A host that cannot report a value meeting the [field
/// validity rule](crate#field-validity) returns [`NSGI_VAR_ERROR`].
pub type NsgiGetVar = unsafe extern "C" fn(
    host_ctx: *mut c_void,
    name: *const u8,
    name_len: usize,
    out_value: *mut *const u8,
    out_value_len: *mut usize,
) -> i32;

/// The canonical type signature of the wakeup callback passed to a body or tunnel read callback.
///
/// The application passes one to [`NsgiRequest::read_body`] and [`NsgiRequest::read_tunnel`], and
/// the host one to [`NsgiResponse::read_body`], each with a `wake_ctx` it receives unchanged.
/// `wake_ctx` is an opaque context pointer, possibly null, owned by whichever passed it; the other
/// does not dereference or free it.
///
/// A call tells whichever passed it that the stream can make progress. It schedules the next read
/// call rather than making it, and does not wait on anything a read call may hold, since it may be
/// called from within one.
pub type NsgiWake = unsafe extern "C" fn(wake_ctx: *mut c_void);

/// A chunk is available. A zero-length chunk is not a legal success.
pub const NSGI_REQUEST_BODY_OK: i32 = 0;
/// The body is complete; no further bytes will follow.
pub const NSGI_REQUEST_BODY_END: i32 = 1;
/// No bytes are available at this moment, and more may follow; the host calls `wake` once that
/// changes.
pub const NSGI_REQUEST_BODY_AGAIN: i32 = 2;
/// The connection ended before the body was complete.
pub const NSGI_REQUEST_BODY_ERROR_TERMINATED: i32 = -1;
/// The body framing was invalid, such as a malformed chunked encoding.
pub const NSGI_REQUEST_BODY_ERROR_PROTOCOL: i32 = -2;
/// The body reached a limit the host enforces.
pub const NSGI_REQUEST_BODY_ERROR_TOO_LARGE: i32 = -3;
/// The host's read timeout fired before the next chunk arrived.
pub const NSGI_REQUEST_BODY_ERROR_TIMEOUT: i32 = -4;

/// The canonical type signature of the host's request body read callback.
///
/// Delivers the request body as chunks borrowed from host memory, one per call, in the order the
/// bytes arrived. `host_ctx` is [`NsgiRequest::host_ctx`] passed back unchanged. `wake` is the
/// application's [`NsgiWake`], receiving `wake_ctx` unchanged, or `None` when the application wants
/// none. On [`NSGI_REQUEST_BODY_OK`] the host writes the chunk pointer and length; on any other
/// status the out-parameters are left untouched.
///
/// Returns one of the `NSGI_REQUEST_BODY_*` statuses.
///
/// # Chunk lifetime
/// A chunk stays valid until the next call for the same request, and never beyond the return of
/// `nsgi_handle`, for a call made during it, or of the request's last `nsgi_free_response` call.
/// The application copies whatever it keeps past that point, such as a fragment spanning a chunk
/// boundary. A call moves past the end of the current chunk rather than reading a requested number
/// of bytes.
///
/// # Terminal statuses
/// Once [`NSGI_REQUEST_BODY_END`] or an error is reported, every later call reports that same
/// status. A request carrying no body reports [`NSGI_REQUEST_BODY_END`] on the first call.
///
/// # Wakeups
/// A call passing a `wake` never waits for the body to make progress, meaning for a chunk, the end
/// of the body or an error to become available, and reports [`NSGI_REQUEST_BODY_AGAIN`] instead. A
/// call passing none waits.
///
/// For every call reporting [`NSGI_REQUEST_BODY_AGAIN`], the host calls that call's `wake` exactly
/// once, as soon as the body can make progress. The application can release `wake_ctx` within that
/// call.
///
/// # Ordering
/// The `wake` call may come from any thread, including one the application did not create, and may
/// precede the return reporting [`NSGI_REQUEST_BODY_AGAIN`]. It comes no later than the host
/// reclaiming the request after [`NsgiCancel`] or calling `nsgi_close_connection` for its
/// connection.
///
/// The application makes its next call only once `wake` has been called and the call reporting
/// [`NSGI_REQUEST_BODY_AGAIN`] has returned, in whichever order. It orders that call after the
/// `wake` call, so that state the host wrote before calling `wake` is visible within it.
///
/// # Host obligations
/// The host answers `Expect: 100-continue` on the first call and not before it.
///
/// Handing over the response does not end the request body: the application may go on calling while
/// the host reads the response, so that the two bodies stream independently, until the request's
/// last `nsgi_free_response` call has returned, and makes no call after that. It may equally leave
/// the body unread; once that return has happened, the host drains the remainder or closes the
/// connection rather than parsing those bytes as a subsequent message.
pub type NsgiReadRequestBody = unsafe extern "C" fn(
    host_ctx: *mut c_void,
    wake_ctx: *mut c_void,
    wake: Option<NsgiWake>,
    out_chunk: *mut *const u8,
    out_chunk_len: *mut usize,
) -> i32;

/// The trailer section is available.
pub const NSGI_REQUEST_TRAILERS_OK: i32 = 0;
/// [`NsgiRequest::read_body`] has not reported [`NSGI_REQUEST_BODY_END`].
pub const NSGI_REQUEST_TRAILERS_ERROR_INCOMPLETE: i32 = -1;

/// The canonical type signature of the host's request trailers read callback.
///
/// Delivers the request trailer section borrowed from host memory. `host_ctx` is
/// [`NsgiRequest::host_ctx`] passed back unchanged. On [`NSGI_REQUEST_TRAILERS_OK`] the host writes
/// the array pointer, null when the length is 0, and length, borrowed for the duration of the
/// `nsgi_handle` call, or, for a call made after that return, until the next `read_trailers` call
/// for the same request and never beyond the return of the request's last `nsgi_free_response`
/// call; on any other status the out-parameters are left untouched.
///
/// The application may call it after handing over the response, on the window
/// [`NsgiReadRequestBody`] describes.
///
/// Returns one of the `NSGI_REQUEST_TRAILERS_*` statuses. A host that received a trailer section
/// breaking the [field validity rule](crate#field-validity) reports
/// [`NSGI_REQUEST_BODY_ERROR_PROTOCOL`] from [`NsgiRequest::read_body`].
pub type NsgiReadRequestTrailers = unsafe extern "C" fn(
    host_ctx: *mut c_void,
    out_trailers: *mut *const NsgiHeader,
    out_trailers_len: *mut usize,
) -> i32;

/// A chunk is available. A zero-length chunk is not a legal success.
pub const NSGI_TUNNEL_OK: i32 = 0;
/// The client closed its sending direction; no further bytes will follow.
pub const NSGI_TUNNEL_END: i32 = 1;
/// No bytes are available at this moment, and more may follow; the host calls `wake` once that
/// changes.
pub const NSGI_TUNNEL_AGAIN: i32 = 2;
/// The exchange did not switch to a tunnel.
pub const NSGI_TUNNEL_ERROR_NOT_SWITCHED: i32 = -1;
/// The tunnel was aborted, or the connection ended, before the client closed its sending direction.
pub const NSGI_TUNNEL_ERROR_TERMINATED: i32 = -2;
/// The host's read timeout fired before the next chunk arrived.
pub const NSGI_TUNNEL_ERROR_TIMEOUT: i32 = -3;

/// The canonical type signature of the host's tunnel read callback.
///
/// A final response can switch the exchange to a tunnel: a bidirectional byte stream that is no
/// longer HTTP, such as a WebSocket. A 101 carrying `upgrade`, naming the protocol switched to,
/// switches an HTTP/1.1 request carrying `upgrade`; HTTP/2 and HTTP/3 have no 101. A 2xx switches a
/// CONNECT request on any version, including an extended CONNECT request, which carries
/// [`NsgiRequest::protocol`].
///
/// Delivers the bytes the client sends through the tunnel after the request message, as chunks
/// borrowed from host memory, one per call, in the order the bytes arrived. The switching
/// response's [`NsgiResponse::read_body`] supplies the bytes the host sends, and the request body
/// still delivers the request's own content, of which a CONNECT request has none. `host_ctx` is
/// [`NsgiRequest::host_ctx`] passed back unchanged. `wake` is the application's [`NsgiWake`],
/// receiving `wake_ctx` unchanged, or `None` when the application wants none. On [`NSGI_TUNNEL_OK`]
/// the host writes the chunk pointer and length; on any other status the out-parameters are left
/// untouched.
///
/// Returns one of the `NSGI_TUNNEL_*` statuses. The application may call it on the window
/// [`NsgiReadRequestBody`] describes.
///
/// # Chunk lifetime
/// A chunk stays valid until the next call for the same request, and never beyond the return of the
/// request's last `nsgi_free_response` call.
///
/// # Terminal statuses
/// Once [`NSGI_TUNNEL_END`] or an error is reported, every later call reports that same status.
///
/// # Wakeups
/// A call passing a `wake` never waits for the tunnel to make progress, meaning for a chunk, the
/// client closing its sending direction or an error to become available, and reports
/// [`NSGI_TUNNEL_AGAIN`] instead. A call passing none waits.
///
/// Until the final response has reached the host, through the out-parameter or through
/// [`NsgiRequest::respond`], the tunnel cannot make progress, so a call passing no `wake` before
/// the application hands over the response waits on the application itself.
///
/// For every call reporting [`NSGI_TUNNEL_AGAIN`], the host calls that call's `wake` exactly once,
/// as soon as the tunnel can make progress. The application can release `wake_ctx` within that
/// call.
///
/// # Ordering
/// The `wake` call may come from any thread, including one the application did not create, and may
/// precede the return reporting [`NSGI_TUNNEL_AGAIN`]. It comes no later than the host reclaiming
/// the request after [`NsgiCancel`] or calling `nsgi_close_connection` for its connection.
///
/// The application makes its next call only once `wake` has been called and the call reporting
/// [`NSGI_TUNNEL_AGAIN`] has returned, in whichever order. It orders that call after the `wake`
/// call, so that state the host wrote before calling `wake` is visible within it.
///
/// # Host obligations
/// Each direction closes on its own. [`NSGI_RESPONSE_BODY_END`] closes the host's sending
/// direction, [`NSGI_TUNNEL_END`] reports that the client closed its own, and
/// [`NSGI_RESPONSE_BODY_ERROR`] aborts both. The host defers the switching response's
/// `nsgi_free_response` call until this callback has reported a terminal status, so the application
/// can go on reading after closing its own direction. The host may instead abandon the tunnel, and
/// one the application stops reading is bounded by the host's idle timeout.
///
/// The host supplies whatever `connection` option the switch requires. A host switching an HTTP/1.1
/// request whose `Expect: 100-continue` it has not answered transmits the 100 ahead of the 101. An
/// HTTP/1.1 connection carries no request after a switch.
pub type NsgiReadTunnel = unsafe extern "C" fn(
    host_ctx: *mut c_void,
    wake_ctx: *mut c_void,
    wake: Option<NsgiWake>,
    out_chunk: *mut *const u8,
    out_chunk_len: *mut usize,
) -> i32;

/// The host accepted the interim response and transmits it ahead of the final response.
pub const NSGI_INFORM_OK: i32 = 0;
/// The host declined the interim response and transmits nothing for it.
pub const NSGI_INFORM_DECLINED: i32 = 1;
/// The interim response is invalid, and the host transmits nothing for it.
pub const NSGI_INFORM_ERROR_INVALID: i32 = -1;
/// The final response has already reached the host.
pub const NSGI_INFORM_ERROR_FINAL: i32 = -2;

/// The canonical type signature of the host's interim response callback.
///
/// Carries an interim response, whose `status` is 1xx. `host_ctx` is [`NsgiRequest::host_ctx`]
/// passed back unchanged. `headers` is null when `headers_len` is 0; the host leaves out any
/// `content-length` it carries.
///
/// Returns one of the `NSGI_INFORM_*` statuses. A host treats a 101, which only a final response
/// carries to switch to a tunnel (see [`NsgiReadTunnel`]), and an interim response breaking the
/// [field validity rule](crate#field-validity), as [`NSGI_INFORM_ERROR_INVALID`]. A call made once
/// the final response has reached the host, through the out-parameter or through
/// [`NsgiRequest::respond`], reports [`NSGI_INFORM_ERROR_FINAL`].
///
/// # Lifetimes
/// The pointers address storage the application owns, borrowed for the duration of the call; the
/// host copies whatever it keeps.
///
/// # Ordering
/// The call may come from any thread, including one the host did not create, and from within
/// `nsgi_handle` on the thread running it.
///
/// # Host obligations
/// The host transmits the interim responses it accepts in the order of the calls. It may decline
/// any of them, and a call it discards reports [`NSGI_INFORM_DECLINED`].
pub type NsgiInform = unsafe extern "C" fn(
    host_ctx: *mut c_void,
    status: u16,
    headers: *const NsgiHeader,
    headers_len: usize,
) -> i32;

/// The canonical type signature of the host's response completion callback.
///
/// Carries the response for a request whose `nsgi_handle` call returned [`NSGI_HANDLE_PENDING`].
/// `host_ctx` is [`NsgiRequest::host_ctx`] passed back unchanged. The application calls it exactly
/// once for every such request, and never for one it answered through the out-parameter.
///
/// # Lifetimes
/// The pointer addresses storage the application owns, borrowed for the duration of the call; the
/// host copies whatever it keeps.
///
/// # Ordering
/// The call may come from any thread, including one the host did not create, and may precede
/// `nsgi_handle` returning [`NSGI_HANDLE_PENDING`], which the host waits for before treating the
/// response as available. It does not come from within `nsgi_handle` on the thread running it,
/// where the application answers through the out-parameter instead, nor from within [`NsgiCancel`].
///
/// The host orders the call so that state the application wrote before making it is visible to the
/// thread that afterwards reads the response and calls its callbacks.
///
/// # Host obligations
/// An application that both made this call and returned [`NSGI_HANDLE_DONE`] produces two
/// responses: the host transmits the one in the out-parameter and passes the other to
/// `nsgi_free_response` without transmitting it.
pub type NsgiRespond = unsafe extern "C" fn(host_ctx: *mut c_void, res: *const NsgiResponse);

/// An HTTP request constructed by the host and passed to the application.
///
/// A host rejects a request whose fields break the [field validity rule](crate#field-validity),
/// with 400 unless a more suitable status applies.
///
/// # Ownership
/// Every pointer field is borrowed from the host for the duration of the `nsgi_handle` call. The
/// application does not free any of them. What a callback writes is borrowed on the window that
/// callback describes.
#[repr(C)]
pub struct NsgiRequest {
    /// One of the `NSGI_SCHEME_*` constants. Describes the hop the host itself terminated; never
    /// derived from `X-Forwarded-Proto`.
    pub scheme: u8,
    /// HTTP major version, 0 when the version is unknown.
    pub http_version_major: u8,
    /// HTTP minor version, 0 when the version is unknown or has no minor part.
    pub http_version_minor: u8,
    /// The transport peer that opened the connection. Null when the host has no peer. Never
    /// derived from `X-Forwarded-For` or `Forwarded`.
    pub peer: *const NsgiAddr,
    /// The local address the connection was accepted on. Null when the host has none.
    pub local: *const NsgiAddr,
    /// Opaque application connection context pointer, possibly null, returned by
    /// `nsgi_open_connection` for the connection the request arrived on. The host does not
    /// dereference or free this.
    pub connection_ctx: *mut c_void,
    /// HTTP method bytes (e.g. `b"GET"`).
    pub method: *const u8,
    pub method_len: usize,
    /// `:protocol` pseudo-header bytes as received (e.g. `b"websocket"`), carried by an extended
    /// CONNECT request. Null when the request carries none. Only a host that has enabled extended
    /// CONNECT, by sending `SETTINGS_ENABLE_CONNECT_PROTOCOL`, accepts such a request.
    pub protocol: *const u8,
    pub protocol_len: usize,
    /// Authority component bytes, as received and including any port. Taken from the request
    /// target when it is in absolute or authority form, otherwise from `:authority` or `Host`. A
    /// host rejects a request whose authority is not of the form `host [ ":" port ]` that RFC 3986
    /// defines, including one carrying the deprecated userinfo subcomponent. Null when the request
    /// conveys no authority.
    pub authority: *const u8,
    pub authority_len: usize,
    /// Path component bytes as received (e.g. `b"/api/v1"`); a host does not percent-decode or
    /// remove dot segments. An absolute-form target with an empty path has a path of `b"/"`, other
    /// than as below.
    ///
    /// A server-wide OPTIONS request, whose target is the asterisk alone or an absolute form with
    /// an empty path, has a path of `b"*"`. A CONNECT request whose target is the authority alone,
    /// carrying no `:path`, has a null path and a `path_len` of 0; one carrying a `:path`, as with
    /// `:protocol`, has that path.
    pub path: *const u8,
    pub path_len: usize,
    /// Query component bytes as received; a host does not percent-decode. The `?` delimiter is
    /// excluded. Null when `query_len` is 0.
    pub query: *const u8,
    pub query_len: usize,
    /// Request headers, carrying no `host` (reported through `authority`), no `content-length`
    /// (through `content_length`), no `transfer-encoding` (already decoded), and no pseudo-header.
    /// Null when `headers_len` is 0.
    pub headers: *const NsgiHeader,
    pub headers_len: usize,
    /// The body length the request declared, or [`NSGI_CONTENT_LENGTH_UNKNOWN`] when it declared
    /// none; a host rejects a request declaring that length. A client may declare a length and
    /// stop sending short of it. A host accepting a request that declares both a length and a
    /// transfer coding reports the length unknown.
    pub content_length: u64,
    /// Opaque host context pointer, possibly null. The application does not dereference or free
    /// this.
    pub host_ctx: *mut c_void,
    /// Host variable lookup, receiving `host_ctx` unchanged. `None` when the host supplies no
    /// variables.
    pub get_var: Option<NsgiGetVar>,
    /// Request body delivery, receiving `host_ctx` unchanged. The host supplies it for every
    /// request, including one that carries no body.
    pub read_body: NsgiReadRequestBody,
    /// Request trailers delivery, receiving `host_ctx` unchanged. The host supplies it for every
    /// request, including one that carries no trailer section.
    pub read_trailers: NsgiReadRequestTrailers,
    /// Tunnel delivery, receiving `host_ctx` unchanged. The host supplies it for every request,
    /// including one that cannot switch to a tunnel.
    pub read_tunnel: NsgiReadTunnel,
    /// Interim response delivery, receiving `host_ctx` unchanged. The host supplies it for every
    /// request.
    pub inform: NsgiInform,
    /// Response completion, receiving `host_ctx` unchanged. The host supplies it for every
    /// request.
    pub respond: NsgiRespond,
}

/// A chunk is available. A zero-length chunk is not a legal success.
pub const NSGI_RESPONSE_BODY_OK: i32 = 0;
/// The body is complete; no further bytes will follow.
pub const NSGI_RESPONSE_BODY_END: i32 = 1;
/// No bytes are available at this moment, and more may follow; the application calls `wake` once
/// that changes.
pub const NSGI_RESPONSE_BODY_AGAIN: i32 = 2;
/// The application failed and the body will not complete. The status code is already committed, so
/// the host leaves the message incomplete rather than completing it.
pub const NSGI_RESPONSE_BODY_ERROR: i32 = -1;

/// The canonical type signature of the application's response body read callback.
///
/// Delivers the response body as chunks borrowed from application memory, one per call. `app_ctx`
/// is [`NsgiResponse::app_ctx`] passed back unchanged. `wake` is the host's [`NsgiWake`], receiving
/// `wake_ctx` unchanged, or `None` when the host wants none. On [`NSGI_RESPONSE_BODY_OK`] the
/// application writes the chunk pointer and length; on any other status the out-parameters are left
/// untouched.
///
/// Returns one of the `NSGI_RESPONSE_BODY_*` statuses.
///
/// # Chunk lifetime
/// A chunk stays valid until the next call for the same response, and never beyond
/// `nsgi_free_response`. A host that transmitted part of a chunk keeps the remainder by not calling
/// again; one coalescing several chunks into a single write copies them.
///
/// # Terminal statuses
/// Once [`NSGI_RESPONSE_BODY_END`] or [`NSGI_RESPONSE_BODY_ERROR`] is reported, every later call
/// reports that same status. A response carrying no body reports [`NSGI_RESPONSE_BODY_END`] on the
/// first call.
///
/// # Wakeups
/// A call passing a `wake` never waits for the body to make progress, meaning for a chunk, the end
/// of the body or an error to become available, and reports [`NSGI_RESPONSE_BODY_AGAIN`] instead. A
/// call passing none waits.
///
/// For every call reporting [`NSGI_RESPONSE_BODY_AGAIN`], the application calls that call's `wake`
/// exactly once, as soon as the body can make progress. The host can release `wake_ctx` within that
/// call.
///
/// # Ordering
/// A call may come from a thread other than the one that ran `nsgi_handle`.
///
/// The `wake` call may come from any thread, including one the host did not create, and may precede
/// the return reporting [`NSGI_RESPONSE_BODY_AGAIN`]. It comes no later than the return of
/// `nsgi_free_response` for the response.
///
/// The host makes its next call only once `wake` has been called and the call reporting
/// [`NSGI_RESPONSE_BODY_AGAIN`] has returned, in whichever order. It orders that call after the
/// `wake` call, so that state the application wrote before calling `wake` is visible within it.
///
/// # Host obligations
/// A host unable to accept more bytes at this moment stops calling until it can, which is the whole
/// of backpressure. It may instead stop permanently and go straight to `nsgi_free_response`;
/// abandonment carries no status. A callback that neither yields nor completes is bounded by the
/// host's idle timeout.
///
/// The host may transmit the status code and header section as soon as the response reaches it.
pub type NsgiReadResponseBody = unsafe extern "C" fn(
    app_ctx: *mut c_void,
    wake_ctx: *mut c_void,
    wake: Option<NsgiWake>,
    out_chunk: *mut *const u8,
    out_chunk_len: *mut usize,
) -> i32;

/// The trailer section is available.
pub const NSGI_RESPONSE_TRAILERS_OK: i32 = 0;
/// The application failed and the trailer section will not complete. The host leaves the message
/// incomplete as for [`NSGI_RESPONSE_BODY_ERROR`].
pub const NSGI_RESPONSE_TRAILERS_ERROR: i32 = -1;

/// The canonical type signature of the application's response trailers read callback.
///
/// Delivers the response trailer section borrowed from application memory. `app_ctx` is
/// [`NsgiResponse::app_ctx`] passed back unchanged. On [`NSGI_RESPONSE_TRAILERS_OK`] the
/// application writes the array pointer, null when the length is 0, and length; on any other status
/// the out-parameters are left untouched.
///
/// Returns one of the `NSGI_RESPONSE_TRAILERS_*` statuses. A host treats a trailer section breaking
/// the [field validity rule](crate#field-validity) as [`NSGI_RESPONSE_TRAILERS_ERROR`]. The
/// application answers without waiting, so it reports [`NSGI_RESPONSE_BODY_END`] only once the
/// trailer section is ready.
///
/// The host calls it at most once, and only when the message framing can carry a trailer section.
///
/// # Ordering
/// The call comes after the [`NsgiResponse::read_body`] call reporting [`NSGI_RESPONSE_BODY_END`]
/// has returned, and the host orders it so that state the application wrote during that call is
/// visible within it.
pub type NsgiReadResponseTrailers = unsafe extern "C" fn(
    app_ctx: *mut c_void,
    out_trailers: *mut *const NsgiHeader,
    out_trailers_len: *mut usize,
) -> i32;

/// An HTTP response constructed by the application and passed to the host.
///
/// A host answers 500 rather than transmitting a response whose fields break the [field validity
/// rule](crate#field-validity), whose headers break the rules [`NsgiResponse::headers`] states, or
/// a 101 that does not switch the exchange to a tunnel as [`NsgiReadTunnel`] describes.
///
/// # Ownership
/// The application owns all memory reachable through it or written by its callbacks, and the host
/// borrows it until the `nsgi_free_response` call that releases it, or on a narrower window the
/// callback describes. The host does not modify or free any field directly.
#[repr(C)]
pub struct NsgiResponse {
    /// HTTP status code of the final response (e.g. `200`, `404`).
    pub status: u16,
    /// Response headers, carrying a valid `content-length` when the application knows the body's
    /// length and never `transfer-encoding`. Null when `headers_len` is 0.
    ///
    /// A transfer coding frames the connection the host terminated, and chunk boundaries are not
    /// message framing. A host transmits a declared length as given, other than one it leaves out
    /// as below, and, for a response carrying content, holds the application to it, treating a
    /// body that ends short of or runs past it as [`NSGI_RESPONSE_BODY_ERROR`]; absent a declared
    /// length it frames the response with whatever its protocol version provides.
    ///
    /// A response to HEAD, and one whose status is 204 or 304, carries no content: the host
    /// transmits none of the body and need not read it. A response to HEAD, or a 304, may still
    /// declare the length its content would have had in a response to the same request made with
    /// GET. The host leaves out any `content-length` a 101, a 204, or a 2xx response to CONNECT,
    /// carries.
    pub headers: *const NsgiHeader,
    pub headers_len: usize,
    /// Opaque application context pointer, possibly null. The host does not dereference or free
    /// this.
    pub app_ctx: *mut c_void,
    /// Response body delivery, receiving `app_ctx` unchanged. The application supplies it for
    /// every response, including one that carries no body. For a response switching the exchange
    /// to a tunnel, it supplies the bytes the host sends through the tunnel after the header
    /// section (see [`NsgiReadTunnel`]).
    pub read_body: NsgiReadResponseBody,
    /// Response trailers delivery, receiving `app_ctx` unchanged. `None` when the application
    /// sends no trailer section.
    pub read_trailers: Option<NsgiReadResponseTrailers>,
}

/// The canonical type signature of the application's connection open function.
///
/// Every NSGI application provides a C ABI function with this signature:
///
/// ```rust,ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn nsgi_open_connection() -> *mut c_void { ... }
/// ```
///
/// The host calls it at most once for each transport connection it terminates. A host without
/// transport connections treats each request as arriving on a connection of its own.
///
/// # Ordering
/// The call returns before any `nsgi_handle` call for a request on that connection begins. The host
/// orders it so that state the application wrote during it is visible within every `nsgi_handle`
/// and `nsgi_close_connection` call that receives the returned context.
pub type NsgiOpenConnection = unsafe extern "C" fn() -> *mut c_void;

/// The response is in the response out-parameter and the request is complete.
pub const NSGI_HANDLE_DONE: i32 = 0;
/// The application supplies the response later through [`NsgiRequest::respond`], and has left the
/// response out-parameter untouched.
pub const NSGI_HANDLE_PENDING: i32 = 1;

/// The canonical type signature of the application's cancellation callback.
///
/// The host calls it at most once, when it has stopped wanting the response. `cancel_ctx` is
/// [`NsgiPending::cancel_ctx`] passed back unchanged.
///
/// The application still calls [`NsgiRequest::respond`] in every case, and the host discards the
/// response to a request it has abandoned. The request's handles keep their meanings after the call
/// and report their own errors. Nothing reaches `cancel_ctx` once `respond` has returned, so that
/// is where the application releases it.
///
/// # Ordering
/// The call never comes before `nsgi_handle` has returned [`NSGI_HANDLE_PENDING`]; a host that
/// detected the condition earlier makes it once that return has happened.
///
/// It never runs concurrently with the request's `respond` call and never follows one, so a
/// `respond` call may be waiting on it: it does not wait on anything that path holds, and does not
/// itself call `respond`.
///
/// The host orders the call so that state the host wrote before making it is visible within it.
/// Against the application's own work on the request it is not ordered at all.
///
/// # Host obligations
/// A host may reclaim a canceled request once this call has returned, after which a `respond` call
/// naming that request, or any other call naming it, is discarded rather than undefined. Reclaiming
/// requires that no value the host has presented as `host_ctx` name a different request while the
/// application may still hold it.
pub type NsgiCancel = unsafe extern "C" fn(cancel_ctx: *mut c_void);

/// The application's registration for cancellation notice, written on [`NSGI_HANDLE_PENDING`].
///
/// The host initializes it to no cancellation before calling `nsgi_handle`, so an application
/// wanting none leaves it untouched. It is the only out-parameter the host writes before the call.
#[repr(C)]
pub struct NsgiPending {
    /// Opaque application context pointer, possibly null. The host does not dereference or free
    /// this.
    pub cancel_ctx: *mut c_void,
    /// Cancellation notice, receiving `cancel_ctx` unchanged. `None` when the application wants
    /// none.
    pub cancel: Option<NsgiCancel>,
}

/// The canonical type signature of the application's entry point.
///
/// Every NSGI application provides a C ABI function with this signature:
///
/// ```rust,ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn nsgi_handle(
///     req: *const NsgiRequest,
///     out_res: *mut NsgiResponse,
///     out_pending: *mut NsgiPending,
/// ) -> i32 { ... }
/// ```
///
/// Returns one of the `NSGI_HANDLE_*` statuses. An application that fails answers with a response
/// rather than a status.
///
/// # Lifetimes
/// `req` addresses storage the host owns; the application does not free it, and does not hold
/// references to it or any of its fields after returning, whichever status it returns.
/// `connection_ctx`, `host_ctx` and the callbacks are values rather than borrowed memory, so an
/// application that copied them out goes on using them afterwards.
pub type NsgiApp = unsafe extern "C" fn(
    req: *const NsgiRequest,
    out_res: *mut NsgiResponse,
    out_pending: *mut NsgiPending,
) -> i32;

/// The canonical type signature of the application's response cleanup function.
///
/// Every NSGI application provides a C ABI function with this signature:
///
/// ```rust,ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn nsgi_free_response(res: *const NsgiResponse) { ... }
/// ```
///
/// The host calls it exactly once for every response the application handed over, through either
/// path and including one carried by a [`NsgiRequest::respond`] call the host discarded, so the
/// application can release whatever it allocated.
///
/// # Lifetimes
/// The pointer addresses storage the host owns, borrowed for the duration of the call: the
/// application releases what the fields point to, not the storage the pointer addresses, and does
/// not retain the pointer past the return.
///
/// # Ordering
/// The call comes after the last call to a callback the response carries and never concurrently
/// with one, whether or not the response reached completion.
pub type NsgiFreeResponse = unsafe extern "C" fn(*const NsgiResponse);

/// The canonical type signature of the application's connection close function.
///
/// Every NSGI application provides a C ABI function with this signature:
///
/// ```rust,ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn nsgi_close_connection(connection_ctx: *mut c_void) { ... }
/// ```
///
/// The host calls it once for each `nsgi_open_connection` call. `connection_ctx` is the value
/// `nsgi_open_connection` returned, passed back unchanged.
///
/// # Ordering
/// The call begins only once the connection has delivered its last request and every `nsgi_handle`
/// and `nsgi_free_response` call for its requests has returned. The host orders it so that state
/// the application wrote during those calls is visible within it.
pub type NsgiCloseConnection = unsafe extern "C" fn(connection_ctx: *mut c_void);
