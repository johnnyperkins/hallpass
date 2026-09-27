#!/bin/sh
# Turn each failed test in a `cargo test` log into an error annotation. Job
# logs need a signed-in viewer; annotations are public, so this is what lets
# anyone see why a run went red.
#
# Captured runs print a failure as a "---- name stdout ----" block. Under
# --nocapture there is no block, so a panic line starts one instead and the
# 40 lines after it (the harness's daemon log excerpt) are its body.
set -eu
log=$1
[ -f "$log" ] || exit 0
awk '
	function esc(s) { gsub(/%/, "%25", s); gsub(/\r/, "", s); return s }
	function flush() {
		if (name == "") return
		t = esc(name); gsub(/:/, "%3A", t); gsub(/,/, "%2C", t)
		b = esc(body); gsub(/\n/, "%0A", b)
		printf "::error title=%s::%s\n", t, substr(b, 1, 4000)
		name = ""; body = ""; left = -1
	}
	/^---- .* stdout ----$/ { flush(); name = $2; next }
	/^failures:$/ || /^test result:/ { flush(); next }
	name == "" && /^thread .* panicked at/ {
		name = $2; gsub(/\047/, "", name); left = 40
	}
	name != "" {
		body = body $0 "\n"
		if (left > 0 && --left == 0) flush()
	}
	END { flush() }
' "$log"
