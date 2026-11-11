FROM golang:1.27-alpine AS build
ARG PROGRAM_VERSION=1.0.0
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X signer/internal/cli.programVersion=${PROGRAM_VERSION}" \
    -o /out/norsign ./cmd/norsign

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/norsign /norsign
USER nonroot:nonroot
ENTRYPOINT ["/norsign"]
