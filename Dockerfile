# --- Stage 1: Build (Obligatoire: Nightly pour l'Edition 2024) ---
FROM rustlang/rust:nightly-slim AS builder

WORKDIR /app

# Dépendances pour la compilation (OpenSSL & Pkg-config)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# On compile en Release avec le compilateur Nightly
RUN cargo build --release

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim
WORKDIR /app

# Installation des certificats et de libssl pour le binaire final
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/bindkey-server .
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080
CMD ["./bindkey-server"]