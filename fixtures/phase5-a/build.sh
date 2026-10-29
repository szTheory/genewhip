#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$ROOT"

case "${1:-}" in
  --validate-only)
    exec python3 -I scripts/fixtures/phase5_candidate.py \
      --verify-slot a --stage materials \
      --eligibility evidence/phase5-eligibility-v2.json
    ;;
  --verify-reproducible)
    exec python3 -I scripts/fixtures/phase5_candidate.py \
      --verify-build-pair \
      --ledger fixtures/candidate-screening-v2.json \
      --eligibility evidence/phase5-eligibility-v2.json \
      --policy fixtures/phase5-policy-v2.json
    ;;
  *)
    printf 'BLOCKED: use --validate-only or --verify-reproducible\n' >&2
    exit 2
    ;;
esac
