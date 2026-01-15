# --- Builder stage ---
FROM rust:1.84-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release

# --- Runtime stage ---
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
# On récupère le binaire et les fichiers de migration
COPY --from=builder /app/target/release/bindkey-server .
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080
# Le serveur lancera les migrations au démarrage ou via un script
CMD ["./bindkey-server"]