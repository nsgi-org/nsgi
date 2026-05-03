//! # NSGI — Native Web Server Gateway Interface
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

/// A single HTTP header name/value pair, stored as raw byte slices.
///
/// # Ownership — when carried by `NsgiRequest`
/// Borrowed from the host. The application must **not** free these fields.
///
/// # Ownership — when carried by `NsgiResponse`
/// Managed entirely by the application. The application may use heap allocation **or**
/// static memory (e.g. `b"Content-Type"`) for `name` and `value` — the host
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

/// An HTTP request constructed by the host and passed to the application.
///
/// # Ownership
/// Every pointer field is borrowed from the host for the duration of the
/// `nsgi_handle` call. The application must not free any of them.
#[repr(C)]
pub struct NsgiRequest {
    /// HTTP method bytes (e.g. `b"GET"`).
    pub method: *const u8,
    pub method_len: usize,
    /// Path component bytes (e.g. `b"/api/v1"`).
    pub path: *const u8,
    pub path_len: usize,
    /// Query component bytes. The `?` delimiter is excluded. Null when absent.
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
}

/// An HTTP response produced by the application and returned to the host.
///
/// # Ownership
/// The application constructs this value and owns all memory reachable through it.
/// The host treats the entire struct as **read-only** — it must not modify or
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
