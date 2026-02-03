# --- Stage 1: Build (Aligné sur Bookworm) ---
FROM rustlang/rust:nightly-bookworm AS builder

WORKDIR /app

# Dépendances pour la compilation
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN echo "Mise à jour du binaire le $(date)" > /build_timestamp.txt
# 1. Copie le dossier .sqlx dans l'image de build
COPY .sqlx .sqlx
# On force SQLx à utiliser les données préparées
ENV SQLX_OFFLINE=true

# On compile en Release
RUN cargo build --release

# --- Stage 2: Runtime (Identique) ---
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# On récupère le binaire
COPY --from=builder /app/target/release/bindkey-server .
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080
CMD ["./bindkey-server"]