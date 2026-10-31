# xSight — Top-level Makefile
# Delegates to sub-project Makefiles (node/ and controller/)

.PHONY: all node controller clean help check

all: node

node:
	$(MAKE) -C node all

controller:
	$(MAKE) -C controller all

clean:
	$(MAKE) -C node clean
	-$(MAKE) -C controller clean

check:
	./scripts/check.sh

help:
	@echo "xSight top-level targets:"
	@echo "  all        — build node (default)"
	@echo "  node       — build xsight-node"
	@echo "  controller — build xsight-controller"
	@echo "  clean      — clean all sub-projects"
	@echo "  check      — run formatting, vet, tests, and race checks"
