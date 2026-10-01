#!/usr/bin/env bash
# Release one package from this monorepo to npm. The name and version come from the
# package's own package.json, so one script serves every package.
#
#   scripts/release.sh dry-run apps/<package>   # list the files that would ship
#   scripts/release.sh publish apps/<package>   # publish (npm asks for 2FA), then tag
#
# Through mise: `mise run publish-dry-run apps/<package>`, `mise run publish apps/<package>`.
#
# Refuses to publish a private package, a version that is already on npm, or a
# package.json with lifecycle scripts that would run during pack, publish or install.
# pnpm's own git checks stay on: publish from a clean main branch.
set -euo pipefail
cd "$(dirname "$0")/.."

die() {
	echo "release.sh: $*" >&2
	exit 1
}

[[ $# -eq 2 ]] || {
	echo "usage: release.sh dry-run|publish <package-dir>" >&2
	exit 2
}
action=$1
dir=${2%/}
pkg="$dir/package.json"
[[ -f "$pkg" ]] || die "no package.json in $dir"
command -v jq >/dev/null || die "jq is required"

name=$(jq -r '.name // empty' "$pkg")
version=$(jq -r '.version // empty' "$pkg")
[[ -n "$name" && -n "$version" ]] || die "$pkg needs a name and a version"
[[ "$(jq -r '.private // false' "$pkg")" == "false" ]] || die "$name is marked private"

hooks=$(jq -r '.scripts // {} | keys[] | select(test("^(pre|post)?(pack|publish|install)$|^prepublishOnly$|^prepare$"))' "$pkg")
[[ -z "$hooks" ]] || die "$name has lifecycle scripts that would run on publish: $(echo $hooks)"

echo "release.sh: $name@$version from $dir"
case $action in
dry-run)
	(cd "$dir" && pnpm pack --dry-run)
	;;
publish)
	if [[ -n "$(pnpm view "$name@$version" version 2>/dev/null)" ]]; then
		die "$name@$version is already on npm; bump the version in $pkg"
	fi
	(cd "$dir" && pnpm publish --access public)
	tag="$name@$version"
	git tag "$tag"
	echo "release.sh: tagged $tag. Push it: git push origin $tag"
	;;
*)
	die "unknown action '$action' (dry-run or publish)"
	;;
esac
