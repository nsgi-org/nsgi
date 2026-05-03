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
