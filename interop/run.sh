#!/bin/sh
# Runs the interoperability tests through a go.work made in a temporary
# directory, so no replace directive is ever committed. The workspace holds
# this module, the parent kolo-moq and, when they are checked out next to
# it, the sibling Kolo repositories; without them the tagged versions in
# go.mod are used. Extra arguments go to "go test".
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
kolo=$(dirname "$root")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
{
	echo "go 1.27"
	echo
	echo "use ("
	echo "	$here"
	echo "	$root"
	for dir in kolo-transport kolo-secure kolo-id kolo-codec; do
		if [ -f "$kolo/$dir/go.mod" ]; then
			echo "	$kolo/$dir"
		fi
	done
	echo ")"
	echo
	# The parent module is untagged; this file is temporary.
	echo "replace github.com/ciranda-dev/kolo-moq v0.0.0-00010101000000-000000000000 => $root"
} >"$work/go.work"
cd "$here"
GOWORK="$work/go.work" go vet ./...
GOWORK="$work/go.work" go test -count=1 "$@" ./...
