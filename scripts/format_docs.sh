#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Format all Markdown documents with mdformat (CommonMark + GFM tables).
#
#   scripts/format_docs.sh          # rewrite in place
#   scripts/format_docs.sh --check  # CI gate (runs after cargo fmt, before clippy)
#
# Requires `mdformat` with the `mdformat-gfm` plugin on PATH (or in ./.venv).
set -euo pipefail

CHECK_ONLY=false
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=true
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

MDFORMAT="mdformat"
if ! command -v "${MDFORMAT}" >/dev/null 2>&1 && [[ -x /Users/lma1980/repository/MuConsole/.venv/bin/mdformat ]]; then
  MDFORMAT="/Users/lma1980/repository/MuConsole/.venv/bin/mdformat"
fi

FILES=()
while IFS= read -r f; do FILES+=("$f"); done < <(
  find . -name "*.md" \
    -not -path "./.git/*" \
    -not -path "./target/*" \
    -not -path "./.agents/*" | sort
)

if [[ "${CHECK_ONLY}" == true ]]; then
  echo "Checking Markdown formatting with mdformat..."
  "${MDFORMAT}" --check --wrap keep "${FILES[@]}"
  echo "All Markdown documents are cleanly formatted."
else
  echo "Formatting Markdown documents with mdformat..."
  "${MDFORMAT}" --wrap keep "${FILES[@]}"
  echo "Formatting complete."
fi
