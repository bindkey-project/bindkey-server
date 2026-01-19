# --- Stage 1: Build ---
FROM rustlang/rust:nightly-slim AS builder

WORKDIR /app

# Dépendances pour la compilation
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# --- LE CHANGEMENT EST ICI ---
# On force SQLx à utiliser les données préparées dans le dossier .sqlx
ENV SQLX_OFFLINE=true

# On compile en Release
RUN cargo build --release

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# On récupère le binaire
COPY --from=builder /app/target/release/bindkey-server .
# Optionnel : si tu as besoin des migrations pour le démarrage
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080
CMD ["./bindkey-server"]