# Rust Tor-like Anonymity Network Client

A Rust implementation of a Tor-like anonymity network client that provides secure, anonymous communication through multi-hop circuits and onion routing.

**Disclaimer:** This project is a toy project for educational purposes only. It is not a secure or anonymous way to access the internet. Do not use it for any real-world anonymous communication.

## Features

*   **Multi-hop Circuit Routing**: Establishes circuits of a configurable number of hops through the Tor network. Relay selection is functional, but the handshake implementation is partial.
*   **Onion Encryption**: The cryptographic foundations for onion encryption are in place, using modern and secure ciphers like AES-256-GCM and x25519 for key exchange. However, it is not yet used to encrypt traffic.
*   **SOCKS5 Proxy Interface**: A functional SOCKS5 proxy is provided, allowing applications to connect to the client. Currently, it relays traffic directly to the destination, bypassing the Tor circuit.
*   **Directory System Integration**: The client can fetch and parse real consensus data from the Tor Project's directory authorities, providing a list of ~9100 relays.

## Getting Started

### Prerequisites

*   [Rust](https://www.rust-lang.org/tools/install)
*   Docker (optional, for easy build/run with dependencies)

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

This will start a SOCKS5 proxy on `127.0.0.1:9050`.

### Testing with curl

To test the SOCKS5 proxy, you can use `curl`:

```bash
curl --socks5-hostname localhost:9050 http://example.com
```

You should see the full HTML response from `example.com`.

### Testing the Client

The project includes a suite of integration tests that verify the functionality of the client. To run the tests:

```bash
# Native test
cargo test

# Or Docker test
docker run --rm tor-client cargo test -- --nocapture
```

The tests have been refactored to use a shared `DirectoryClient`, which significantly improves test execution time by fetching the consensus data only once.

## Architecture

The client is composed of several key components:

*   **Directory Client**: Responsible for fetching and parsing the network consensus from the Tor Project's directory authorities. It maintains a list of available relays, their flags (e.g., `Guard`, `Exit`), and bandwidth information.
*   **Circuit Manager**: Manages the creation and lifecycle of circuits. It selects relays for each hop in the circuit and is responsible for performing the handshake with each relay.
*   **SOCKS5 Proxy**: Provides a SOCKS5 interface for applications to connect to the client. It handles SOCKS5 protocol negotiation and is intended to route traffic through the established circuits.
*   **Crypto**: Contains the cryptographic primitives for the Tor protocol, including the ntor handshake, and AES-256-GCM for onion encryption.
*   **Network**: Handles the low-level network communication, including TLS connections to relays and the framing of cells.

## Development Status & TODO

The project is under active development. Here is a list of the current status and future work:

- [x] Fetch and parse real consensus data.
- [x] Select relays and build a circuit.
- [ ] Implement the full ntor handshake, including `CREATE2` and `CREATED2` cells.
- [ ] Route stream data through the circuit using `RELAY` cells.
- [ ] Implement backward crypto for processing responses.
- [ ] Add support for pluggable transports.
- [ ] Add support for hidden services.
- [ ] Integrate a metrics and logging framework for better observability.
- [ ] Add support for IPv6 addresses.

## Contributing

Contributions are welcome! The most immediate area for improvement is the full implementation of the circuit-level communication. Pull requests that focus on this area are particularly appreciated.

## License

This project is licensed under the [MIT License](LICENSE).
