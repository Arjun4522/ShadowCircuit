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

# Run the project
CMD ["cargo", "run"]
