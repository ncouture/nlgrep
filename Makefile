BINARY := nlgrep
PKG := ./cmd/nlgrep

.PHONY: build test cover vet fmt lint clean release-dry-run

build:
	go build -o bin/$(BINARY) $(PKG)

test:
	go test ./... -race

cover:
	go test ./... -race -coverprofile=coverage.out
	go tool cover -func=coverage.out

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint:
	golangci-lint run

clean:
	rm -rf bin/ dist/ coverage.out

release-dry-run:
	goreleaser release --snapshot --clean
