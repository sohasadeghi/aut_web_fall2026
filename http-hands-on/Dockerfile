FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/proxy ./cmd/proxy \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mint ./cmd/mint

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/proxy /proxy
COPY --from=builder /out/mint /mint
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/proxy"]
