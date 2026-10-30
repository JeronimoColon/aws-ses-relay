#!/usr/bin/env bash
# Checks that Cargo.toml's hand-written feature lists for aws-sdk-s3 and
# aws-sdk-sesv2 still equal each crate's own default features minus `rustls`.
#
# Those two crates are declared with `default-features = false` so the SDK's
# legacy TLS stack (pulled in by `rustls`) stays out of the build. That freezes
# the list: a default feature AWS adds later would not reach the relay. This
# check fails when the copy drifts from the crate's real defaults, so the list
# gets a deliberate update instead of silently falling behind.
#
# If a crate goes back to a plain version string (uses its defaults again),
# there is no pin to check and it passes; deny.toml's bans still keep the
# legacy stack out.
#
# Needs cargo and jq. Run from the repository root.
set -euo pipefail

pinned_crates=(aws-sdk-s3 aws-sdk-sesv2)
excluded_feature="rustls"

metadata=$(cargo metadata --format-version 1 --locked)
problems=0

for crate in "${pinned_crates[@]}"; do
  dependency=$(jq --arg crate "$crate" \
    '.packages[] | select(.name == "aws-ses-relay") | .dependencies[] | select(.name == $crate)' \
    <<<"$metadata")

  uses_default_features=$(jq -r '.uses_default_features' <<<"$dependency")
  if [[ "$uses_default_features" == "true" ]]; then
    echo "$crate: uses its default features; no pin to check"
    continue
  fi

  pinned_features=$(jq -r '.features | sort | join(", ")' <<<"$dependency")
  expected_features=$(jq -r --arg crate "$crate" --arg excluded "$excluded_feature" \
    '.packages[] | select(.name == $crate) | .features.default | map(select(. != $excluded)) | sort | join(", ")' \
    <<<"$metadata")

  if [[ "$pinned_features" == "$expected_features" ]]; then
    echo "$crate: pinned features match its defaults minus $excluded_feature"
  else
    echo "$crate: pinned features do not match its defaults minus $excluded_feature" >&2
    echo "  Cargo.toml lists: [$pinned_features]" >&2
    echo "  expected:         [$expected_features]" >&2
    echo "  Update the feature list in Cargo.toml (keep $excluded_feature out)." >&2
    problems=$((problems + 1))
  fi
done

if [[ "$problems" -gt 0 ]]; then
  exit 1
fi
