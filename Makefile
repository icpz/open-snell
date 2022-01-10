BINDIR=build
PKGDIR=$(CURDIR)
VERSION=$(shell git describe --tags --dirty --always || echo "unknown version")
GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)
GOBUILD=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags '-X "github.com/icpz/open-snell/constants.Version=$(VERSION)" -w -s'
TARGETS := server client

SRCS := $(shell find $(PKGDIR) -name '*.go')

all: $(TARGETS)

$(BINDIR)/%: $(SRCS) go.mod go.sum
	$(GOBUILD) -o $@ $(PKGDIR)/cmd/$(@:$(BINDIR)/%=%)

clean/%:
	rm -f $(@:clean/%=$(BINDIR)/%)

.SECONDEXPANSION:
$(TARGETS): $(BINDIR)/snell-$$@

clean: $$(patsubst %,clean/snell-%,$$(TARGETS))

version:
	@echo $(VERSION)
