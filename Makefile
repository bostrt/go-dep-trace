APP=dep-trace

.PHONY: build
build: clean
	go build -o ${APP} main.go

.PHONY: run
run:
	go run main.go

.PHONY: clean
clean:
	go clean
