# xSight Node — Build targets

# Tools
CLANG      ?= clang
STRIP      ?= $(shell for b in llvm-strip llvm-strip-20 llvm-strip-19 llvm-strip-18 llvm-strip-17; do command -v $$b && break; done)
GO         ?= go

# BPF settings
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf
BPF_SRC    := bpf/xsight.c
BPF_HDR    := bpf/xsight.h
BPF_OBJ    := bpf/xsight.elf

# Go settings
BIN := bin/xsight-node

.PHONY: all bpf generate build clean help

all: generate build

## BPF — manual clang compilation (for debugging / bpftool inspection)
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@
	@if [ -n "$(STRIP)" ]; then $(STRIP) -g $@; else echo "note: no llvm-strip; $(STRIP) leaving debug info"; fi

## Generate — bpf2go (produces type-safe Go bindings)
generate:
	BPF2GO_STRIP="$(STRIP)" $(GO) generate ./internal/bpf/

## Build — xsight-node binary
build: generate
	$(GO) build -o $(BIN) .

## Clean
clean:
	rm -f $(BPF_OBJ) $(BIN)
	rm -f internal/bpf/xsight_bpf*.go internal/bpf/xsight_bpf*.o

## Help
help:
	@echo "Targets:"
	@echo "  all      — generate + build"
	@echo "  bpf      — compile BPF C to ELF (manual, for bpftool)"
	@echo "  generate — run bpf2go (generates Go bindings)"
	@echo "  build    — build xsight-node binary"
	@echo "  clean    — remove build artifacts"
