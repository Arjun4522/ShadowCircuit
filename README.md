
# Rust Tor-like Anonymity Network Client

A Rust implementation of a Tor-like anonymity network client that provides secure, anonymous communication through multi-hop circuits and onion routing.

**Disclaimer:** This project is a toy project for educational purposes only. It is not a secure or anonymous way to access the internet. Do not use it for any real-world anonymous communication.

## Features

*   Multi-hop circuit routing (in progress)
*   Onion encryption (in progress)
*   SOCKS5 proxy interface (partially functional)
*   Pluggable transports (not implemented)
*   Directory system integration (partially functional)
*   Hidden services support (not implemented)

## Getting Started

### Prerequisites

*   [Rust](https://www.rust-lang.org/tools/install)

### Building

```bash
cargo build
```

### Running

```bash
cargo run
```

This will start a SOCKS5 proxy on `localhost:9051`.

### Testing

```bash
cargo test
```
