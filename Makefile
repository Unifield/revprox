# Use this makefile to create the binaries for checking into OpenERP Web,
# so that they get an auditable version compiled into them.

go=go

# Thanks, Jessfraz.
# https://github.com/jessfraz/amicontained/blob/master/Makefile
GITCOMMIT := $(shell git rev-parse --short HEAD)
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GITUNTRACKEDCHANGES),)
	GITCOMMIT := $(GITCOMMIT)-dirty
endif

all: build

build: clean revprox revprox.exe

clean:
	rm -f revprox revprox.exe

# If dep is not installed do: "go get -u github.com/golang/dep/cmd/dep"
vendor:
	dep ensure

revprox: vendor
	$(go) build -ldflags "-s -w -X main.gitRevision=$(GITCOMMIT)"

revprox.exe: vendor
	GOARCH=386 GOOS=windows $(go) build -ldflags "-s -w -X main.gitRevision=$(GITCOMMIT)"
