# Use this makefile to create the binaries for checking into OpenERP Web,
# so that they get an auditable version compiled into them.

rev=$(shell git rev-parse --short HEAD)

all: revprox revprox.exe

clean:
	rm -f revprox revprox.exe

revprox:
	GOOS=linux go build -ldflags "-X main.gitRevision=$(rev)"

revprox.exe:
	GOOS=windows go build -ldflags "-X main.gitRevision=$(rev)"
