# Use this makefile to create the binaries for checking into OpenERP Web,
# so that they get an auditable version compiled into them.

go=go1.8.3
rev=$(shell git rev-parse --short HEAD)

all: build

build: clean revprox revprox.exe

clean:
	rm -f revprox revprox.exe

vendor:
	dep ensure

revprox: vendor
	GOOS=linux $(go) build -ldflags "-s -w -X main.gitRevision=$(rev)"

revprox.exe: vendor
	GOARCH=386 GOOS=windows $(go) build -ldflags "-s -w -X main.gitRevision=$(rev)"
