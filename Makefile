BIN 		:= opa-spicedb
IMAGE_NAME	:= opa-spicedb
REPOSITORY 	:= umbrellaassociates
VERSION 	:= 0.3
GO		:= /usr/lib/go-1.24/bin/go

IMAGE=$(REPOSITORY)/$(IMAGE_NAME)

.PHONY: docker-build docker-push 


build: build-go
build-go:
	$(GO) build -o $(BIN) .

build-static:
	$(GO) build -ldflags="-linkmode external -extldflags=-static" -o $(BIN) .


docker-build:
	docker build --pull -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

docker-build-dev:
	docker build --pull -t $(IMAGE):dev .

docker-push:
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

docker-push-dev:
	docker push $(IMAGE):dev

