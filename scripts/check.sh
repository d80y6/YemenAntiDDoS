#!/bin/bash
set -uo pipefail

root=$(git rev-parse --show-toplevel) && cd "$root" || exit 1
passed=0
failed=0
skipped=0

result() {
    printf '%s %s\n' "$1" "$2"
    case "$1" in
        PASS) passed=$((passed + 1)) ;;
        FAIL) failed=$((failed + 1)) ;;
        SKIP) skipped=$((skipped + 1)) ;;
    esac
}

run() {
    local step=$1
    shift
    if "$@"; then
        result PASS "$step"
    else
        result FAIL "$step"
    fi
}

check_fmt() {
    local fmt_dir enum_status count file count_status output_status io_status fmt_status gofmt_bin
    local -a statuses
    # Resolve gofmt even when only the `go` binary is on PATH (common with a
    # bare /usr/local/bin/go symlink): fall back to GOROOT's bundled gofmt.
    gofmt_bin=$(command -v gofmt || true)
    if [ -z "$gofmt_bin" ] && command -v go >/dev/null 2>&1; then
        gofmt_bin="$(go env GOROOT)/bin/gofmt"
    fi
    if [ -z "$gofmt_bin" ] || [ ! -x "$gofmt_bin" ]; then
        printf '%s\n' 'fmt: gofmt not found on PATH or in $(go env GOROOT)/bin'
        return 1
    fi
    fmt_dir=$(mktemp -d) || return 1
    git ls-files -z -- 'controller/*.go' 'node/*.go' 'shared/*.go' >"$fmt_dir/files" 2>"$fmt_dir/enum.err"
    enum_status=$?
    count=0
    while IFS= read -r -d '' file; do
        count=$((count + 1))
    done <"$fmt_dir/files"
    count_status=$?
    printf 'fmt: %s Go files found\n' "$count"
    output_status=$?
    statuses=(1 1)
    {
        git ls-files -z -- 'controller/*.go' 'node/*.go' 'shared/*.go' | xargs -0 "$gofmt_bin" -l
        statuses=("${PIPESTATUS[@]}")
    } >"$fmt_dir/out" 2>"$fmt_dir/err"
    io_status=$?
    fmt_status=1
    if [ "$enum_status" -eq 0 ] && [ "$count_status" -eq 0 ] && [ "$count" -gt 0 ] &&
        [ "$output_status" -eq 0 ] && [ "$io_status" -eq 0 ] &&
        [ "${statuses[0]}" -eq 0 ] && [ "${statuses[1]}" -eq 0 ] &&
        [ ! -s "$fmt_dir/out" ]; then
        fmt_status=0
    else
        if [ "$count" -eq 0 ]; then
            printf '%s\n' 'no Go files found'
        fi
        printf 'fmt: enumeration=%s count=%s output=%s io=%s git=%s xargs=%s\n' "$enum_status" "$count_status" "$output_status" "$io_status" "${statuses[0]}" "${statuses[1]}"
        cat "$fmt_dir/out" "$fmt_dir/enum.err" "$fmt_dir/err"
    fi
    rm -rf "$fmt_dir" || return 1
    return "$fmt_status"
}

in_module() {
    local module=$1
    shift
    (cd "$module" && "$@")
}

run fmt check_fmt
run ctl-vet in_module controller go vet ./...
run ctl-test in_module controller go test ./... -count=1
# The internal/api race suite alone measures ~10.5 min — above go test's
# default 10-minute package timeout — so the race pass raises the budget.
run ctl-race in_module controller go test -race ./... -count=1 -timeout=20m
run shared-vet in_module shared go vet ./...
run shared-test in_module shared go test ./... -count=1

platform=$(uname -s)
platform_status=$?
if [ "$platform_status" -ne 0 ]; then
    printf 'Platform detection failed: uname -s exited with status %s.\n' "$platform_status"
    result FAIL node-vet
    result FAIL node-test
elif [ "$platform" != Linux ]; then
    result SKIP node-vet
    result SKIP node-test
elif [ ! -f node/internal/bpf/xsight_x86_bpfel.o ]; then
    printf '%s\n' 'BPF object missing; run scripts/build-node.sh bpf first (requires node/bpf/vmlinux.h).'
    result FAIL node-vet
    result FAIL node-test
else
    run node-vet in_module node go vet ./...
    run node-test in_module node go test ./... -count=1
fi

printf 'check: %s passed, %s failed, %s skipped\n' "$passed" "$failed" "$skipped"
if [ "$failed" -gt 0 ]; then
    exit 1
fi
exit 0
