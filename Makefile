IMAGE := aididalam/bidly-auth
PLATFORMS := linux/amd64,linux/arm64

ifndef TAG
$(error TAG is required. Usage: make TAG=main-1)
endif

.PHONY: all build test

all: test build

test:
	go test ./...

build:
	docker buildx build --platform $(PLATFORMS) --tag $(IMAGE):$(TAG) --push .
