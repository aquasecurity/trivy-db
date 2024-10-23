FROM golang:1.22-alpine as builder

WORKDIR /build
COPY . /build
SHELL ["/bin/sh", "-o", "pipefail", "-c"]

RUN apk --no-cache add make gzip

RUN go install
RUN make db-fetch-langs
RUN make db-fetch-vuln-list
RUN make build
RUN make db-build
RUN make db-compact
RUN make db-compress

FROM scratch
COPY --from=builder /build/assets/db.tar.gz .
