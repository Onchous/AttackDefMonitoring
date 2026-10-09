# Build frontend
FROM node:24-alpine AS frontend_builder
RUN apk add --no-cache git
WORKDIR /app
COPY ./web/ /app
RUN yarn install --frozen-lockfile && yarn build

# Build backend
FROM golang:1.26 AS backend_builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./ ./
COPY --from=frontend_builder /app/dist ./web/dist
RUN go build -o ./bin/pkappa2 ./cmd/pkappa2/main.go

# Run
FROM ubuntu:latest
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 python3 python3-dev python3-pip && rm -rf /var/lib/apt/lists/*
COPY converters/pkappa2lib/requirements.txt requirements.txt
RUN python3 -m pip install --break-system-packages --upgrade -r requirements.txt

COPY --from=backend_builder /app/bin/pkappa2 ./pkappa2
COPY --from=backend_builder /app/web/dist ./web/dist

# The original image's adduser allocated UID/GID 1001 after Ubuntu's
# built-in 1000 account. Keep that identity for existing /data volumes.
RUN groupadd --gid 1001 pkappa2 && useradd --uid 1001 --gid pkappa2 --create-home pkappa2
RUN mkdir -p /data /pcaps_in /app/converters && chown pkappa2:pkappa2 /data /pcaps_in /app/converters
USER pkappa2

EXPOSE 8080
VOLUME /data
VOLUME /pcaps_in
VOLUME /app/converters

ENV PKAPPA2_BASE_DIR="/data"
ENV PKAPPA2_WATCH_DIR="/pcaps_in"
ENV PKAPPA2_ADDRESS=":8080"

ENTRYPOINT [ "/app/pkappa2" ]
