# Use this makefile to create the binaries for checking into OpenERP Web,
# so that they get an auditable version compiled into them.

go=go1.8
rev=$(shell git rev-parse --short HEAD)

all: build

build: clean revprox revprox.exe

clean:
	rm -f revprox revprox.exe

revprox:
	GOOS=linux $(go) build -ldflags "-s -w -X main.gitRevision=$(rev)"

revprox.exe:
	GOOS=windows $(go) build -ldflags "-s -w -X main.gitRevision=$(rev)"
