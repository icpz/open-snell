BINDIR=build
PKGDIR=$(CURDIR)
GOBUILD=CGO_ENABLED=0 go build -trimpath -ldflags '-w -s'

all: server client

server client:
	$(GOBUILD) -o $(BINDIR)/snell-$@ $(PKGDIR)/cmd/snell-$@

