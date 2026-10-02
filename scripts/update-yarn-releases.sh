#!/usr/bin/env bash
set -euo pipefail

# Refresh apps/am-i-hacked/bin/yarn-releases.tsv — the version -> sha256 table
# of package/bin/yarn.js for every stable release of the npm package
# @yarnpkg/cli-dist. The scanner pins Yarn by content hash, so the table is
# regenerated from the registry and never edited by hand.
#
# For every stable version the table does not already cover, the release
# tarball is downloaded into a scratch directory, checked against the
# registry's sha512 dist.integrity before it is trusted, and then only
# package/bin/yarn.js is extracted and hashed. Nothing downloaded is executed.
# Any download or integrity failure is fatal; the table is replaced atomically.
#
# Run: mise run update-yarn-releases

REGISTRY_URL="https://registry.npmjs.org/@yarnpkg/cli-dist"
TARBALL_URL_PREFIX="https://registry.npmjs.org/@yarnpkg/cli-dist/-/cli-dist-"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TABLE="$ROOT/apps/am-i-hacked/bin/yarn-releases.tsv"

WORK="$(mktemp -d)"
OUT_TMP=""
cleanup() {
	rm -rf "$WORK"
	[[ -z "$OUT_TMP" ]] || rm -f "$OUT_TMP"
}
trap cleanup EXIT

die() {
	printf 'update-yarn-releases: %s\n' "$1" >&2
	exit 1
}

sha256_stdin() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum | cut -d' ' -f1
	else
		shasum -a 256 | cut -d' ' -f1
	fi
}

for tool in curl jq tar openssl sort; do
	command -v "$tool" >/dev/null 2>&1 || die "required tool '$tool' not found on PATH"
done

[[ -f "$TABLE" ]] || die "table not found: $TABLE"

curl -fsSL --output "$WORK/registry.json" "$REGISTRY_URL" ||
	die "failed to download $REGISTRY_URL"

jq -r '
	.versions
	| to_entries[]
	| select(.key | contains("-") | not)
	| select(.value.dist.integrity != null)
	| "\(.key)\t\(.value.dist.integrity)"
' "$WORK/registry.json" >"$WORK/versions.tsv" ||
	die "failed to parse registry metadata with jq"

# The table's leading comment lines are carried over verbatim.
comments=()
while IFS= read -r line; do
	[[ "$line" == \#* ]] || break
	comments+=("$line")
done <"$TABLE"

rows=()
while IFS=$'\t' read -r version hash; do
	[[ -n "$version" ]] || continue
	[[ "$version" == \#* ]] && continue
	[[ -n "$hash" ]] || die "malformed row in $TABLE: $version"
	rows+=("$version"$'\t'"$hash")
done <"$TABLE"

added=0
while IFS=$'\t' read -r version integrity; do
	[[ -n "$version" ]] || continue
	# Check if version already exists in the rows array using grep
	if ((${#rows[@]} > 0)) && printf '%s\n' "${rows[@]}" | cut -f1 | grep -qxF -- "$version"; then
		continue
	fi

	[[ "$integrity" == sha512-* && -n "${integrity#sha512-}" ]] ||
		die "no usable sha512 integrity for $version in the registry metadata"

	printf 'update-yarn-releases: fetching %s\n' "$version" >&2
	tgz="$WORK/cli-dist-$version.tgz"
	curl -fsSL --output "$tgz" "${TARBALL_URL_PREFIX}${version}.tgz" ||
		die "failed to download tarball for $version"

	expected="${integrity#sha512-}"
	actual="$(openssl dgst -sha512 -binary "$tgz" | openssl base64 -A)" ||
		die "failed to hash tarball for $version"
	[[ "$actual" == "$expected" ]] || die "integrity mismatch for $version"

	hash="$(tar -xzOf "$tgz" package/bin/yarn.js | sha256_stdin)" ||
		die "failed to extract package/bin/yarn.js from $version"

	rows+=("$version"$'\t'"$hash")
	added=$((added + 1))
done <"$WORK/versions.tsv"

OUT_TMP="$(mktemp "$TABLE.tmp.XXXXXX")"
{
	if ((${#comments[@]} > 0)); then
		printf '%s\n' "${comments[@]}"
	fi
	if ((${#rows[@]} > 0)); then
		printf '%s\n' "${rows[@]}" | LC_ALL=C sort -V
	fi
} >"$OUT_TMP"
mv "$OUT_TMP" "$TABLE"
OUT_TMP=""

printf 'update-yarn-releases: added %d, total %d\n' "$added" "${#rows[@]}"
