BINDIR=build
PKGDIR=$(CURDIR)
GOBUILD=CGO_ENABLED=0 go build -trimpath -ldflags '-w -s'
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
