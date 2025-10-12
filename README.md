# Rust Tor-like Anonymity Network Client

A Rust implementation of a Tor-like anonymity network client that provides secure, anonymous communication through multi-hop circuits and onion routing.

**Disclaimer:** This project is a toy project for educational purposes only. It is not a secure or anonymous way to access the internet. Do not use it for any real-world anonymous communication. Traffic currently bypasses the circuit for direct relaying.

## Features

*   Multi-hop circuit routing (partial: relay selection functional; handshakes mocked)
*   Onion encryption (partial: keys/nonces generated; not yet used for traffic)
*   SOCKS5 proxy interface (functional: accepts connections, parses requests, relays directly)
*   Pluggable transports (not implemented)
*   Directory system integration (functional: fetches and parses real consensus from Tor Collector, ~9100 relays)
*   Hidden services support (not implemented)

## Getting Started

### Prerequisites

*   [Rust](https://www.rust-lang.org/tools/install)
*   Docker (for easy build/run with dependencies)

### Building

```bash
# Native build
cargo build --release

# Or Docker build
docker build -t tor-client .
```

### Running

```bash
# Native run
cargo run --release

# Or Docker run (with debug logging)
docker run -it --rm -p 9050:9050 -e RUST_LOG=debug tor-client
```

This will start a SOCKS5 proxy on `127.0.0.1:9050`. Bind to `0.0.0.0:9050` in code for Docker port mapping.

### Testing with curl

```bash
curl --socks5-hostname localhost:9050 http://example.com
```

Expected: Full HTML response from example.com (direct relay).

### Testing

```bash
cargo test
```

## Architecture

- **Directory Client**: Fetches hourly consensus from Tor Project Collector; parses ~9100 relays with flags (Guard/Exit/etc.) and bandwidth weighting.
- **Circuit Manager**: Selects hops (e.g., Guard → Middle → Exit); generates per-hop `OnionCrypto` (AES-256-GCM keys/nonces); mocks handshakes.
- **SOCKS5 Proxy**: Handles auth, CONNECT requests; creates 3-hop circuit; relays via direct TCP (TODO: integrate circuit forwarding).
- **Crypto**: Ring-based AEAD for forward encryption (backward unused); X25519-DH ready for NTor handshakes.

## TODO

- Implement real NTor handshakes (CREATE/EXTEND cells, DH key exchange).
- Route streams via circuit (RELAY_BEGIN to exit; layered encrypt/decrypt).
- Add backward crypto for responses.
- Integrate metrics reporting.
- Support IPv6 addresses in requests.
- Fetch microdescriptors for real onion keys.

## Contributing

Pull requests welcome! Focus on circuit integration for anonymity.

## License

[MIT](LICENSE)