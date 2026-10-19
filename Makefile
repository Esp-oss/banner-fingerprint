.PHONY: build test fmt run-server run-client up down logs client smoke

build:
	go build -o bin/server ./cmd/server
	go build -o bin/client ./cmd/client

test:
	go test ./...

fmt:
	gofmt -w cmd internal

run-server:
	go run ./cmd/server -addr :7070 -rules ./rules

run-client:
	go run ./cmd/client -in ./testdata/input.json -server http://127.0.0.1:7070

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f server

client:
	docker compose --profile client run --rm client

smoke:
	curl -s http://127.0.0.1:7070/health
	curl -s -X POST http://127.0.0.1:7070/fingerprint \
		-H "Content-Type: application/json" \
		-d '[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]'
