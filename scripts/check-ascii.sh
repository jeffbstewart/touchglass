#!/bin/sh
# Presubmit: every tracked file is 7-bit ASCII.  Tab and LF are the
# only control characters allowed; everything else printable must be
# in the space..tilde range.  Run from the repository root.
set -eu

TAB=$(printf '\t')
if git ls-files -z | LC_ALL=C xargs -0 grep -n "[^${TAB} -~]" --; then
  echo "check-ascii: non-ASCII or control bytes found (listed above)" >&2
  exit 1
fi
echo "check-ascii: OK"
