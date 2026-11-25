#!/usr/bin/env bash
#
# Keep package-manager metadata for non-Rust SDKs in lockstep with the Cargo
# workspace version. Release workflows run this before building artifacts so a
# single Cargo.toml bump drives every SDK package version.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

workspace_version="$(
  awk '
    /^\[workspace\.package\][[:space:]]*$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
      line = $0
      sub(/^[^"]*"/, "", line)
      sub(/".*$/, "", line)
      print line
      exit
    }
  ' Cargo.toml
)"

if [[ -z "$workspace_version" ]]; then
  echo "could not find [workspace.package].version in Cargo.toml" >&2
  exit 1
fi

if [[ ! "$workspace_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "workspace version is not valid semver: $workspace_version" >&2
  exit 1
fi

# maturin (and PEP 440) reject SemVer pre-release identifiers the workspace
# uses, such as 0.21.1-sudo.7. Map those to a local version (0.21.1+sudo.7).
# Well-known PEP 440 pre-release labels are normalized instead of being
# treated as local versions.
pep440_version() {
  local ver="$1"
  local base pre build
  build=""
  if [[ "$ver" == *+* ]]; then
    build="+${ver#*+}"
    ver="${ver%%+*}"
  fi
  if [[ "$ver" != *-* ]]; then
    printf '%s%s\n' "$ver" "$build"
    return
  fi
  base="${ver%%-*}"
  pre="${ver#*-}"
  case "$pre" in
    a[0-9]*|a.*|b[0-9]*|b.*|c[0-9]*|c.*|rc*|dev*|alpha*|beta*|preview*|pre[0-9]*|pre.*)
      # 0.13.0-rc.1 -> 0.13.0rc1
      pre="$(printf '%s' "$pre" | tr -d .)"
      printf '%s%s%s\n' "$base" "$pre" "$build"
      ;;
    *)
      # 0.21.1-sudo.7 -> 0.21.1+sudo.7; keep any existing build tag as +foo.bar
      if [[ -n "$build" ]]; then
        printf '%s+%s.%s\n' "$base" "$pre" "${build#+}"
      else
        printf '%s+%s\n' "$base" "$pre"
      fi
      ;;
  esac
}

tag_version=""
if [[ "${GITHUB_REF_TYPE:-}" == "tag" && -n "${GITHUB_REF_NAME:-}" ]]; then
  tag_version="${GITHUB_REF_NAME#v}"
elif [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
  tag_name="${GITHUB_REF#refs/tags/}"
  tag_version="${tag_name#v}"
fi

if [[ -n "$tag_version" && "$tag_version" != "$workspace_version" ]]; then
  echo "tag version ($tag_version) does not match Cargo workspace version ($workspace_version)" >&2
  exit 1
fi

update_file() {
  local file="$1"
  local kind="$2"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/sync-sdk-version.XXXXXX")"

  case "$kind" in
    pyproject)
      awk -v version="$pep440_version" '
        /^\[project\][[:space:]]*$/ { in_project = 1 }
        /^\[/ && $0 !~ /^\[project\][[:space:]]*$/ { in_project = 0 }
        in_project && /^[[:space:]]*version[[:space:]]*=/ {
          print "version = \"" version "\""
          changed = 1
          next
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    cargo-package)
      # The pyo3 crate's version must be PEP 440; it cannot inherit the
      # workspace SemVer pre-release (maturin parses Cargo.toml directly).
      awk -v version="$pep440_version" '
        /^\[package\][[:space:]]*$/ { in_package = 1 }
        /^\[/ && $0 !~ /^\[package\][[:space:]]*$/ { in_package = 0 }
        in_package && /^[[:space:]]*version[[:space:]]*=/ {
          print "version = \"" version "\""
          changed = 1
          next
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    gemspec)
      awk -v version="$workspace_version" '
        !changed && /^[[:space:]]*spec\.version[[:space:]]*=/ {
          sub(/"[^"]+"/, "\"" version "\"")
          changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    cabal)
      # Cabal's version: field is PVP — dot-separated integers only — and rejects
      # the semver prerelease/build suffixes the validation above accepts (e.g.
      # v0.13.0-rc.1). Strip the suffix so a prerelease tag still produces a cabal
      # file that builds; the X.Y.Z prefix is what PVP cares about.
      local cabal_version="${workspace_version%%[-+]*}"
      if [[ "$cabal_version" != "$workspace_version" ]]; then
        echo "stripping semver suffix for cabal version: $workspace_version -> $cabal_version" >&2
      fi
      awk -v version="$cabal_version" '
        !changed && /^version:[[:space:]]*/ {
          print "version:            " version
          changed = 1
          next
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    package-json)
      awk -v version="$workspace_version" '
        !changed && /^[[:space:]]*"version"[[:space:]]*:/ {
          sub(/"version"[[:space:]]*:[[:space:]]*"[^"]+"/, "\"version\": \"" version "\"")
          changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    csproj)
      awk -v version="$workspace_version" '
        !changed && /<Version>[^<]+<\/Version>/ {
          sub(/<Version>[^<]+<\/Version>/, "<Version>" version "</Version>")
          changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    swift-package)
      awk -v version="$workspace_version" '
        !changed && /^let secretSpecBinaryVersion = / {
          print "let secretSpecBinaryVersion = \"" version "\""
          changed = 1
          next
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    gradle-properties)
      awk -v version="$workspace_version" '
        !changed && /^[[:space:]]*secretspec\.version[[:space:]]*=/ {
          sub(/secretspec\.version[[:space:]]*=[[:space:]]*[^#]*/, "secretspec.version=" version "-SNAPSHOT")
          changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    mix-exs)
      awk -v version="$workspace_version" '
        !changed && /^[[:space:]]*version:[[:space:]]*"[^"]+",/ {
          sub(/version:[[:space:]]*"[^"]+",/, "version: \"" version "\",")
          changed = 1
        }
        { print }
        END { if (!changed) exit 1 }
      ' "$file" > "$tmp"
      ;;
    *)
      echo "unknown manifest kind: $kind" >&2
      rm -f "$tmp"
      exit 1
      ;;
  esac

  mv "$tmp" "$file"
}

pep440_version="$(pep440_version "$workspace_version")"
if [[ "$pep440_version" != "$workspace_version" ]]; then
  echo "mapping workspace version to PEP 440 for Python: $workspace_version -> $pep440_version" >&2
fi

update_file secretspec-py/pyproject.toml pyproject
update_file secretspec-py/Cargo.toml cargo-package
update_file secretspec-rb/secretspec.gemspec gemspec
update_file secretspec-hs/secretspec.cabal cabal
update_file secretspec-node/package.json package-json
update_file secretspec-dotnet/src/SecretSpec/SecretSpec.csproj csproj
update_file secretspec-dotnet/tests/SecretSpec.PackageSmoke/SecretSpec.PackageSmoke.csproj csproj
update_file secretspec-jvm/gradle.properties gradle-properties
update_file Package.swift swift-package
update_file secretspec-ex/mix.exs mix-exs

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "PROJECT_VERSION=$workspace_version" >> "$GITHUB_ENV"
fi

echo "synced SDK package versions to $workspace_version"
