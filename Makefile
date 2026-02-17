.PHONY: build build-dev build-prod run dev dev-api dev-fe dev-watch \
       test clean install build-fe fmt check \
       docker-up docker-down docker-build docker-logs docker-clean

# ── Local Development ────────────────────────────────────────────────
#
#   make dev        → starts API + Vite in parallel (open http://localhost:5173)
#   make dev-fe     → frontend only   (assumes API already running)
#   make dev-api    → backend only
#   make dev-watch  → backend with auto-reload (needs: cargo install cargo-watch)

## Run backend + frontend in parallel (recommended for local dev)
dev:
	@echo "→ API on http://localhost:8473"
	@echo "→ App on http://localhost:5173 (proxies /api → :8473)"
	@$(MAKE) -j2 dev-api dev-fe

## Run only the backend
dev-api:
	cargo run --bin fishnet

## Run only the frontend (Vite dev server, proxies /api to backend)
dev-fe:
	cd dashboard && npm run dev

## Run backend with auto-reload on file changes
dev-watch:
	cargo watch -x 'run --bin fishnet'

# ── Build ────────────────────────────────────────────────────────────

## Build the Rust backend (release)
build:
	cargo build --release

## Build the Rust backend (debug)
build-dev:
	cargo build

## Build single production binary with embedded dashboard
build-prod: build-fe
	cargo build --release --features embed-dashboard

## Build the frontend for production
build-fe:
	cd dashboard && npm run build

## Install frontend dependencies
install:
	cd dashboard && npm install

# ── Quality ──────────────────────────────────────────────────────────

## Run Rust tests
test:
	cargo test

## Format Rust code
fmt:
	cargo fmt

## Run clippy lints
check:
	cargo clippy -- -D warnings

## Remove all build artifacts
clean:
	cargo clean
	rm -rf dashboard/dist

# ── Docker ───────────────────────────────────────────────────────────

## Build and start the container
docker-up:
	docker compose up --build -d

## Stop the container
docker-down:
	docker compose down

## Build Docker image without starting
docker-build:
	docker compose build

## Tail container logs
docker-logs:
	docker compose logs -f

## Remove container, volume, and image
docker-clean:
	docker compose down -v --rmi local
