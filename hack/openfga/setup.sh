#!/usr/bin/env bash
# Brings up local OpenFGA, loads the TrustLoop Phase 0 authorization model,
# writes test tuples, and runs verification checks against it.
#
# This is the one documented, repeatable path referenced by ROADMAP.md
# Phase 0 -- "OpenFGA running locally... Done when the model is loaded and
# you've verified it behaves correctly." Nothing here is a one-off command
# typed into a terminal and forgotten: run this script any time (fresh
# clone, after a reboot, in CI) and it gets you to the same verified state.
#
# Usage: hack/openfga/setup.sh
#   (run from anywhere -- it cd's to the repo root itself)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

compose_file="deploy/openfga/docker-compose.yml"

echo "== starting OpenFGA (docker compose) =="
docker compose -f "$compose_file" up -d

echo
echo "== waiting for OpenFGA health check =="
container="trustloop-openfga"
for i in $(seq 1 30); do
  status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "starting")
  echo "  [$i/30] health: $status"
  if [ "$status" = "healthy" ]; then
    break
  fi
  if [ "$i" = "30" ]; then
    echo "OpenFGA did not become healthy in time -- check 'docker logs $container'" >&2
    exit 1
  fi
  sleep 2
done

echo
echo "== writing model + test tuples, then verifying checks =="
go run ./cmd/openfga-verify

echo
echo "== done =="
echo "OpenFGA HTTP API:  http://localhost:8080"
echo "OpenFGA Playground: http://localhost:3000/playground"
echo "Stop it with: docker compose -f $compose_file down"
