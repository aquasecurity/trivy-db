FROM golang:1.13-alpine as builder

ARG DB_TYPE=trivy

WORKDIR /build
COPY . /build
SHELL ["/bin/ash", "-o", "pipefail", "-c"]

RUN apk --no-cache add make

RUN DB_TYPE=${DB_TYPE} make db-all

FROM scratch
COPY --from=builder /build/assets/trivy*.db.gz .
