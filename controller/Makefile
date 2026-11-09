# xSight Controller — Build targets

GO ?= go

BIN := bin/xsight-controller

PROTO_DIR := ../proto
PB_DIR    := internal/pb

.PHONY: all build proto migrate clean help

all: build

## Build — xsight-controller binary
build:
	$(GO) build -o $(BIN) .

## Proto — regenerate the message types from the shared protobuf definition.
## Only xsight.pb.go is regenerated: xsight_grpc.pb.go is PINNED to the
## protoc-gen-go-grpc v1.6.1 output (the locally installed plugin is older
## and would downgrade the committed file). Do not add a --go-grpc_out here
## without upgrading the plugin to v1.6.1+ first.
proto:
	@mkdir -p $(PB_DIR)
	protoc -I $(PROTO_DIR) \
		--go_out=$(PB_DIR) --go_opt=paths=source_relative \
		--go_opt=Mxsight.proto=github.com/d80y6/YemenDDoS/controller/internal/pb \
		$(PROTO_DIR)/xsight.proto

## Migrate — run DB migrations (embedded in binary, just starts and exits)
migrate:
	$(GO) run . -config config.yaml -migrate

## Clean
clean:
	rm -f $(BIN)
	rm -f $(PB_DIR)/xsight.pb.go  # pinned xsight_grpc.pb.go is kept

## Help
help:
	@echo "Targets:"
	@echo "  all      — build (default)"
	@echo "  build    — build xsight-controller binary"
	@echo "  proto    — generate Go code from protobuf"
	@echo "  migrate  — run database migrations"
	@echo "  clean    — remove build artifacts"
