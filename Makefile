.PHONY: run build test docker-build clean

run:
	go run main.go

build:
	go build -o ping main.go

test:
	go test -v ./...

docker-build:
	docker build -t ping:latest .

clean:
	rm -f ping
