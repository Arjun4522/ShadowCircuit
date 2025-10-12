FROM rust:latest

# Install OpenSSL and pkg-config
RUN apt-get update && apt-get install -y libssl-dev pkg-config

# Update rustc and cargo
RUN rustup update

# Create a new directory for the project
WORKDIR /usr/src/tor-client

# Copy the project files into the container
COPY . .

# Build the project
RUN cargo build

# Expose the SOCKS5 port
EXPOSE 9050

# Set environment variable for logging
ENV RUST_LOG=info

# Run the project
CMD ["cargo", "run"]