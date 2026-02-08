.PHONY: build run dev test test-v cover clean tidy

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	go build -ldflags "-X sneaker/cmd.Version=$(VERSION)" -o sneaker .

run: build
	./sneaker serve

dev:
	go run . serve --dev

test:
	go test ./...

test-v:
	go test -v ./...

cover:
	go test -cover ./...

race:
	go test -race ./...

tidy:
	go mod tidy

clean:
	rm -f sneaker *.test
