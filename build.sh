#!/bin/sh

# The script requires:
# - rockcraft
# - skopeo (from rockcraft snap)
# - yq
# - podman

set -e

SKOPEO="/snap/rockcraft/current/bin/skopeo"
if [ ! -x "$SKOPEO" ]; then
  SKOPEO="skopeo"
fi

VERSION=$(yq -r '.version' rockcraft.yaml)
ROCK_FILE="secure-token-service_${VERSION}_amd64.rock"

rockcraft clean
rockcraft pack -v

echo "$IMAGE built"

# Load into podman for local container-structure-tests
if command -v podman >/dev/null 2>&1; then
  podman load -i "$ROCK_FILE"
  podman tag "localhost/${VERSION}:latest" "$IMAGE"
fi

if [ "${PUSH_IMAGE}" = "true" ]; then
  $SKOPEO --insecure-policy copy "oci-archive:${ROCK_FILE}" "docker://$IMAGE"
  echo "$IMAGE pushed"
fi


