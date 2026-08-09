# NSGI: Native Web Server Gateway Interface

A language-agnostic gateway interface protocol over C ABI. This crate provides the `#![no_std]`, zero-dependency Rust definitions of the NSGI protocol types and function signatures.

## Types

| Type | Role |
| ---- | ---- |
| `NsgiHeader` | A single HTTP header name/value pair |
| `NsgiRequest` | HTTP request passed from host to application |
| `NsgiResponse` | HTTP response returned from application to host |
| `NsgiApp` | Type alias for the `nsgi_handle` entry point signature |
| `NsgiFreeResponse` | Type alias for the `nsgi_free_response` cleanup signature |

## License

MIT
