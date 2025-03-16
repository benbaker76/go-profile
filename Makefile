tools:
	BPF_CFLAGS='-D__TARGET_ARCH_x86' go generate ./cmd/profile/

test:
	go test ./cmd/profile -v

build:
	docker build -t benbaker76/go-profile:latest .

run:
	docker run --rm -it --privileged benbaker76/go-profile:latest bash
