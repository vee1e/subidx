.PHONY: all ui build test vet serve dev clean

all: build

# Rebuild the dashboard UI (output is committed at internal/web/dist).
ui:
	cd internal/web && npm ci && npm run build

build: go build -o subidx .

test: go test -race -count=1 ./...

vet: go vet ./...

serve: go run . serve -store ./data -addr 127.0.0.1:8099

dev:
	cd internal/web && SUBIDX_API=$${SUBIDX_API:-http://127.0.0.1:8080} npm run dev

clean:
	rm -f subidx
