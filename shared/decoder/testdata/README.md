# packet-fixtures.json — decoder byte-compatibility fixtures

These fixtures pin the byte-level behaviour of the xSight decoders (the `DECODER_SWITCH` and `parse_ip` logic in `node/bpf/xsight.c`). One fixture file is consumed by every implementation that must classify packets the same way, so any divergence fails a test instead of drifting silently.

## Ownership

- This repository holds the source of truth (this directory).
- Other projects that match on the same decoders (for example the XDrop decoder contract test) copy the file and do not modify it.
- When decoder semantics change in `xsight.c`, update the fixtures and the xSight-side tests first, then the consumers.

## Schema

`packet-fixtures.json` is a JSON object:

```json
{
  "_comment": "free text",
  "version": 1,
  "generated_by": "path of the generator",
  "fixtures": [
    {
      "name": "unique_string_identifier",
      "hex": "hex_encoded_packet_bytes_starting_from_eth_or_ip_header",
      "frame_type": "ethernet" | "ip",
      "expected_decoders": ["tcp", "tcp_ack"],
      "expected_is_invalid": false,
      "expected_is_bad_fragment": false,
      "notes": "why this fixture exists, especially for edge cases"
    }
  ]
}
```

`version` is set in `generate.go`; raise it there when the fixture contract changes. `version: 0` marks an ungenerated scaffold and makes `TestFixtureJSONInSync` skip.

### Fixture fields

- `name`: globally unique, snake_case. Conventional prefixes: `tcp_`, `udp_`, `icmp_`, `gre_`, `esp_`, `igmp_`, `frag_`, `invalid_`, `pod_` (ping-of-death fragment).
- `hex`: packet bytes as a hex string without separators. Starts at L2 when `frame_type` is `ethernet`, at the IP header when it is `ip`.
- `frame_type`: `"ethernet"` or `"ip"`; consumers may use different parse entry points.
- `expected_decoders`: decoder names whose counters `DECODER_SWITCH` must increment (excluding additive labels such as fragment / anomaly).
- `expected_is_invalid`: expected `is_invalid` output of `parse_ip`.
- `expected_is_bad_fragment`: expected `is_bad_fragment` output of `parse_ip`.
- `notes`: one line explaining the purpose, boundary value or counter-example.

## Coverage rules

Each decoder has at least:

- **one positive case**: the most typical matching packet;
- **one positive variant**: a form that is easy to exclude by mistake (for example `tcp_ack_with_psh`, the main ACK-flood shape);
- **one negative case**: a neighbouring packet the contract excludes (for example `tcp_syn_ack`, which is not `tcp_ack`);
- **boundary values** for the anomaly decoders: ping-of-death `frag_end` 65535 vs 65536, tiny TCP payload 19 vs 20, IHL 4 vs 5, TCP data offset 4 vs 5.

## Regenerating

Do not write hex by hand and do not edit `packet-fixtures.json` directly. `generate.go` builds the bytes with the Go standard library only (`encoding/binary`, `encoding/hex`), so the `shared` module stays dependency-free. From the repository root:

```bash
cd shared/decoder/testdata
go run generate.go          # writes packet-fixtures.json in this directory
cd ..
go test ./...               # TestGoParityMatchesFixtures and TestFixtureJSONInSync must pass
```

`generate.go` carries a `//go:build ignore` tag and there is no `//go:generate` directive; run it by hand. Its fixture definitions are kept in sync with `allTestFixtures()` in `shared/decoder/contract_test.go`, which also contains the Go parity implementation (`goParityParse`). When `xsight.c` changes:

1. Update the expectations in `allTestFixtures()`.
2. Update the matching fixture definitions in `generate.go`.
3. Raise `version` in `generate.go` if the contract changed, then run `go run generate.go` to rewrite `packet-fixtures.json`.
4. Run `go test ./...` in `shared/decoder` and check that `TestGoParityMatchesFixtures` and `TestFixtureJSONInSync` pass.

## Consumers

- **xSight**: `shared/decoder/contract_test.go` checks the Go parity implementation against `expected_decoders` and that the on-disk JSON matches the generator.
- **XDrop**: its BPF decoder contract test installs a rule for each decoder, sends the fixture packets and asserts whether the BPF program matches.
