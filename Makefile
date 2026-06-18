.PHONY: build test vet fmt lint clean all

build:
	go build -o patchflow .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	go vet ./... && go test ./...

clean:
	rm -f patchflow

all: fmt vet test build
