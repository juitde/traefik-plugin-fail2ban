export GO11MODULE=on

default: fmt lint test

SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

.PHONY: lint
lint:
	golangci-lint run

.PHONY: fmt
fmt:
	gofumpt -l -w $(SRC)

.PHONY: test
test:
	go test -v -cover ./...

.PHONY: yaegi_test
yaegi_test:
	yaegi test -v .

.PHONY: vendor
vendor:
	go mod vendor

.PHONY: clean
clean:
	rm -rf ./vendor
