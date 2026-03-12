# ─── Stage 1: build ───────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

ARG VERSION=dev

WORKDIR /app

# Cache module downloads independently from source changes.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath \
      -ldflags "-X main.version=${VERSION} -w -s" \
      -o /app/go-drp .

# ─── Stage 2: runtime ─────────────────────────────────────────────────────────
# distroless/static: no shell, no package manager, minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app/go-drp /go-drp

# Run as the built-in nonroot user (uid 65532).
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/go-drp"]
