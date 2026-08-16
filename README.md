# NSGI: Native Web Server Gateway Interface

A language-agnostic gateway interface protocol over C ABI. This crate provides the `#![no_std]`, zero-dependency Rust definitions of the NSGI protocol types and function signatures.

## Types

| Type | Role |
| ---- | ---- |
| `NsgiAddr` | A transport address in binary form |
| `NsgiHeader` | A single HTTP header name/value pair |
| `NsgiRequest` | HTTP request passed from host to application |
| `NsgiResponse` | HTTP response returned from application to host |
| `NsgiApp` | Type alias for the `nsgi_handle` entry point signature |
| `NsgiFreeResponse` | Type alias for the `nsgi_free_response` cleanup signature |
| `NsgiGetVar` | Type alias for the host variable lookup carried on `NsgiRequest` |
| `NsgiReadRequestBody` | Type alias for the host request body read callback carried on `NsgiRequest` |

## License

MIT
