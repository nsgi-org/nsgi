//! # NSGI: Native Web Server Gateway Interface
//!
//! This crate provides the C ABI types and function pointer signature that form the NSGI protocol.
//! It is `#![no_std]` and has zero dependencies.
//!
//! NSGI is a language-agnostic gateway interface protocol that connects any C ABI host with
//! application logic written in any language supporting FFI.
//!
//! ## NSGI String Data Convention
//!
//! **All** text and data fields in this protocol are represented as a pair:
//! a raw byte pointer (`*const u8`) and a length (`usize`). They are **NOT** null-terminated.
//! Both the host and the application **must** rely entirely on the companion `_len` field to
//! determine the extent of the data; never pass these pointers to functions that expect C strings.

#![no_std]

use core::ffi::c_void;

/// URL scheme values for `NsgiRequest::scheme`.
pub const NSGI_SCHEME_UNKNOWN: u8 = 0;
pub const NSGI_SCHEME_HTTP: u8 = 1;
pub const NSGI_SCHEME_HTTPS: u8 = 2;
/// A scheme the host terminated but cannot represent here. A host reporting this
/// **must** supply `NsgiRequest::get_var` and answer `request.scheme`.
pub const NSGI_SCHEME_OTHER: u8 = 3;

/// Address family values for `NsgiAddr::family`.
///
/// These are NSGI values, **not** the platform's `AF_*` constants, which differ across
/// operating systems. `UNSPEC` means a connection exists whose address is not
/// representable here, which is distinct from a null `NsgiAddr` pointer.
pub const NSGI_AF_UNSPEC: u8 = 0;
pub const NSGI_AF_INET: u8 = 1;
pub const NSGI_AF_INET6: u8 = 2;
pub const NSGI_AF_UNIX: u8 = 3;

/// A transport address in binary form.
///
/// # Ownership
/// Borrowed from the host. The application must **not** free these fields.
#[repr(C)]
pub struct NsgiAddr {
    /// One of the `NSGI_AF_*` constants.
    pub family: u8,
    /// Port in **host** byte order; 0 when not applicable. Note that
    /// `sockaddr_in::sin_port` is network byte order.
    pub port: u16,
    /// IPv6 interface index, as carried by `sockaddr_in6::sin6_scope_id`.
    /// 0 when unknown or not applicable.
    pub scope_id: u32,
    /// Address bytes in network byte order, IPv4 in the first 4; unused bytes are zero.
    /// The host **must** unmap IPv4-mapped IPv6 addresses (`::ffff:0:0/96`) to `NSGI_AF_INET`.
    pub octets: [u8; 16],
    /// UNIX socket path bytes. Null unless `family` is `NSGI_AF_UNIX`;
    /// an unnamed socket has a `path_len` of 0.
    pub path: *const u8,
    pub path_len: usize,
}

/// A single HTTP header name/value pair, stored as raw byte slices.
///
/// # Ownership: when carried by `NsgiRequest`
/// Borrowed from the host. The application must **not** free these fields.
///
/// # Ownership: when carried by `NsgiResponse`
/// Managed entirely by the application. The application may use heap allocation **or**
/// static memory (e.g. `b"Content-Type"`) for `name` and `value`; the host
/// never interprets or frees these bytes. The host simply passes the enclosing
/// `NsgiResponse` back to `nsgi_free_response`, letting the application clean up
/// according to its own allocation strategy.
#[repr(C)]
pub struct NsgiHeader {
    /// Header name bytes (e.g. `b"Content-Type"`).
    pub name: *const u8,
    pub name_len: usize,
    /// Header value bytes (e.g. `b"text/plain"`).
    pub value: *const u8,
    pub value_len: usize,
}

/// `NsgiGetVar` found the variable. A zero `*out_value_len` means a known but empty value.
pub const NSGI_VAR_OK: i32 = 0;
/// The host does not recognize the variable, as distinct from a known but empty value.
pub const NSGI_VAR_UNKNOWN: i32 = 1;
/// The lookup failed. Negative values are reserved for errors.
pub const NSGI_VAR_ERROR: i32 = -1;

/// The canonical type signature of the host's variable lookup callback.
///
/// Carries connection and server metadata such as `tls.version`, `tls.cipher`,
/// `server.software`, `proxy_protocol.src_addr`. Names are lowercase ASCII,
/// dot-separated, and compared bytewise. Request headers are **not** available here;
/// they are already in `NsgiRequest::headers`.
///
/// `host_ctx` is `NsgiRequest::host_ctx` passed back unchanged. On `NSGI_VAR_OK` the host
/// writes a pointer and length borrowed for the duration of the `nsgi_handle` call; on any
/// other return the out-params are left untouched.
pub type NsgiGetVar = unsafe extern "C" fn(
    host_ctx: *mut c_void,
    name: *const u8,
    name_len: usize,
    out_value: *mut *const u8,
    out_value_len: *mut usize,
) -> i32;

/// An HTTP request constructed by the host and passed to the application.
///
/// # Ownership
/// Every pointer field is borrowed from the host for the duration of the
/// `nsgi_handle` call. The application must not free any of them.
#[repr(C)]
pub struct NsgiRequest {
    /// One of the `NSGI_SCHEME_*` constants. Describes the hop the host itself terminated;
    /// never derived from `X-Forwarded-Proto`.
    pub scheme: u8,
    /// HTTP major version. Both version fields are 0 when the version is unknown, and the
    /// canonical textual forms are `HTTP/0.9`, `HTTP/1.0`, `HTTP/1.1`, `HTTP/2` and `HTTP/3`.
    pub http_version_major: u8,
    /// HTTP minor version, 0 for major versions from 2 onward, which have no minor version.
    pub http_version_minor: u8,
    /// The transport peer that opened the connection. Null when the host has no peer.
    /// Never derived from `X-Forwarded-For` or `Forwarded`.
    pub peer: *const NsgiAddr,
    /// The local address the connection was accepted on. Null when the host has none.
    pub local: *const NsgiAddr,
    /// HTTP method bytes (e.g. `b"GET"`).
    pub method: *const u8,
    pub method_len: usize,
    /// Path component bytes (e.g. `b"/api/v1"`).
    pub path: *const u8,
    pub path_len: usize,
    /// Query component bytes. The `?` delimiter is excluded. Null when `query_len` is 0.
    pub query: *const u8,
    pub query_len: usize,
    /// Request headers borrowed from the host. Null when `headers_len` is 0.
    pub headers: *const NsgiHeader,
    pub headers_len: usize,
    /// Request body bytes. Null when `body_len` is 0.
    pub body: *const u8,
    pub body_len: usize,
    /// Opaque host context pointer. The application must not dereference or free this.
    pub host_ctx: *mut c_void,
    /// Host variable lookup, receiving `host_ctx` unchanged. `None` when the host supplies
    /// no variables.
    pub get_var: Option<NsgiGetVar>,
}

/// An HTTP response produced by the application and returned to the host.
///
/// # Ownership
/// The application constructs this value and owns all memory reachable through it.
/// The host treats the entire struct as **read-only**; it must not modify or
/// free any field directly. Once the host has finished reading the response, it
/// **must** call `nsgi_free_response` (provided by the application) exactly once
/// so the application can release whatever it allocated.
#[repr(C)]
pub struct NsgiResponse {
    /// HTTP status code (e.g. `200`, `404`).
    pub status: u16,
    /// Response headers constructed by the application. Null when `headers_len` is 0.
    pub headers: *const NsgiHeader,
    pub headers_len: usize,
    /// Response body bytes. Null when `body_len` is 0.
    pub body: *const u8,
    pub body_len: usize,
}

/// The canonical type signature of an NSGI application entry point.
///
/// Every NSGI application must provide a C ABI function with this signature:
///
/// ```rust,ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn nsgi_handle(req: *const NsgiRequest) -> NsgiResponse { ... }
/// ```
///
/// # Execution Constraints
///
/// - **Synchronous**: The function must be strictly synchronous.
/// - **Lifetimes**: The application must not hold references to `req` or any of its fields after returning.
/// - **Thread Safety**: The host may invoke this entry point concurrently from multiple OS threads.
///   The implementation must be reentrant and must not rely on unsynchronized mutable state.
/// - **No Panics**: Unwinding into the host is Undefined Behavior.
///   Catch panics internally or use `panic = "abort"`.
pub type NsgiApp = unsafe extern "C" fn(*const NsgiRequest) -> NsgiResponse;

/// The canonical type signature of the NSGI response cleanup function.
///
/// Every NSGI application must provide a C ABI function with this signature:
///
/// ```rust,ignore
/// #[no_mangle]
/// pub unsafe extern "C" fn nsgi_free_response(res: NsgiResponse) { ... }
/// ```
///
/// The host **must** call this exactly once after consuming each `NsgiResponse`,
/// so the application can release whatever it allocated.
pub type NsgiFreeResponse = unsafe extern "C" fn(NsgiResponse);
