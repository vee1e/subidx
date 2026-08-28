.PHONY: all ui build test vet serve dev clean

all: build

# Build the dashboard UI for a separate host (Vercel, Render, or any
# static host). Point it at the subidx API with VITE_API_BASE; the
# binary no longer embeds or serves the UI.
ui:
	cd frontend && npm ci && npm run build

build: go build -o subidx .

test: go test -race -count=1 ./...

vet: go vet ./...

serve: go run . serve -store ./data -addr 127.0.0.1:8099

dev:
	cd frontend && SUBIDX_API=$${SUBIDX_API:-http://127.0.0.1:8080} npm run dev

clean:
	rm -f subidx
