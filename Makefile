BINDIR=build
PKGDIR=$(CURDIR)
GOBUILD=go build

all: server client

server client:
	$(GOBUILD) -o $(BINDIR)/snell-$@ $(PKGDIR)/cmd/snell-$@

