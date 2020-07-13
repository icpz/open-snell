BINDIR=build
PKGDIR=$(CURDIR)
GOBUILD=CGO_ENABLED=0 go build -trimpath -ldflags '-w -s'
TARGETS := server client

SRCS := $(shell find $(PKGDIR) -name '*.go')

all: $(TARGETS)

$(BINDIR)/%: $(SRCS)
	$(GOBUILD) -o $@ $(PKGDIR)/cmd/$(@:$(BINDIR)/%=%)

clean-$(BINDIR)/%:
	rm -f $(@:clean-%=%)

.SECONDEXPANSION:
$(TARGETS): $(BINDIR)/snell-$$@

clean: $$(patsubst %,clean-$$(BINDIR)/snell-%,$$(TARGETS))
