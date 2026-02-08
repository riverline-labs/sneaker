FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN go build -ldflags "-X sneaker/cmd.Version=${VERSION}" -o /sneaker .

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /sneaker /usr/local/bin/sneaker
VOLUME /data
EXPOSE 7657
ENTRYPOINT ["sneaker"]
CMD ["serve", "--db", "/data/sneaker.db"]
