#!/usr/bin/env bash
# Builds the TrustLoop gateway scaffold (issue #3), deploys it to the local
# k3d cluster via its own Helm chart, and proves -- for real, against a live
# SPIRE deployment, not just unit tests -- that it correctly extracts the
# SPIFFE identity of a peer presenting a real SPIRE-issued SVID, and
# correctly rejects a peer that doesn't present one.
#
# This is the one documented, repeatable path for issue #3, following the
# exact same pattern as hack/spire/setup.sh and hack/openfga/setup.sh:
# nothing here is a one-off command typed into a terminal and forgotten.
#
# What this script does, in order:
#   1. Reuses (or creates) the trustloop-dev k3d cluster.
#   2. Runs hack/spire/setup.sh -- idempotent and safe to re-run -- to
#      guarantee SPIRE server+agent are up AND the sample workload
#      (trustloop-sample/sample-workload) has its registration entry. This
#      script's "valid peer" verification reuses that identity rather than
#      minting a second one (see deploy/gateway/verify-job.yaml).
#   3. Creates a SPIRE registration entry for the gateway itself
#      (k8s:ns:trustloop-gateway, k8s:sa:gateway) -- the gateway's OWN
#      identity, distinct from the sample workload's.
#   4. Cross-compiles cmd/gateway and cmd/gateway-verify for linux/amd64,
#      builds a container image (deploy/gateway/Dockerfile), and loads it
#      into the k3d cluster with `k3d image import` -- no registry involved.
#   5. Installs deploy/gateway/chart via Helm (per trustloop/CLAUDE.md:
#      Helm, not hand-rolled kubectl, for this repo's own gateway too).
#   6. Runs deploy/gateway/verify-job.yaml (kubectl apply, not part of the
#      Helm release -- a throwaway verification fixture, same pattern as
#      deploy/spire/sample-workload.yaml) and prints its PASS/FAIL output.
#      Exits non-zero if the Job failed or any check inside it failed.
#
# Usage: hack/gateway/setup.sh
#   (run from anywhere -- it cd's to the repo root itself)
set -euo pipefail

# Same reasoning as hack/spire/setup.sh: this script also runs
# `kubectl exec ... -- /opt/spire/bin/spire-server ...` directly (to create
# the gateway's own registration entry), and on Windows/Git Bash MSYS
# rewrites that Linux-container path into a Windows host path before
# kubectl ever sees it unless this is set. No-op on Linux/macOS.
export MSYS_NO_PATHCONV=1

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

cluster_name="trustloop-dev"
kube_context="k3d-${cluster_name}"

trust_domain="trustloop-dev.local"          # matches deploy/spire/values.yaml
gateway_namespace="trustloop-gateway"
gateway_service_account="gateway"
gateway_spiffe_id="spiffe://${trust_domain}/ns/${gateway_namespace}/sa/${gateway_service_account}"

sample_namespace="trustloop-sample"          # matches hack/spire/setup.sh
sample_service_account="sample-workload"

image_name="trustloop-gateway:dev"
chart_dir="deploy/gateway/chart"
values_file="deploy/gateway/chart/values.yaml"
verify_job_manifest="deploy/gateway/verify-job.yaml"

kctl() { kubectl --context "$kube_context" "$@"; }

echo "== ensuring SPIRE (server/agent) and the sample workload's registration entry exist =="
# hack/spire/setup.sh is idempotent -- safe to run every time this script
# runs, not just the first time. This is also what creates/reuses the
# trustloop-dev k3d cluster itself, so this script doesn't duplicate that
# logic.
hack/spire/setup.sh

echo
echo "== creating the SPIRE registration entry for the gateway's OWN identity =="
spire_server_pod="$(kctl -n spire-server get pod -l app.kubernetes.io/name=server -o jsonpath='{.items[0].metadata.name}')"
spire_server_bin() {
  kctl -n spire-server exec "$spire_server_pod" -- /opt/spire/bin/spire-server "$@"
}

# Same reasoning as hack/spire/setup.sh's sample-workload entry: pin
# -parentID to the already-attested agent's own SPIFFE ID, looked up live
# rather than hand-typed, so it can't silently drift from whatever node k3d
# actually created.
agent_spiffe_id="$(spire_server_bin agent list | grep 'SPIFFE ID' | head -1 | sed -E 's/^SPIFFE ID\s*:\s*//')"
if [ -z "$agent_spiffe_id" ]; then
  echo "could not determine the attested agent's SPIFFE ID from 'spire-server agent list'" >&2
  exit 1
fi

if spire_server_bin entry show -spiffeID "$gateway_spiffe_id" | grep -q "Entry ID"; then
  echo "registration entry for $gateway_spiffe_id already exists -- leaving it as-is"
else
  # Selectors, not a hand-typed workload ID -- any pod in $gateway_namespace
  # running as $gateway_service_account gets this identity automatically,
  # including across pod restarts/redeploys. Same K8s workload attestor
  # mechanism as the sample workload's entry, just a different
  # namespace/service-account pair.
  spire_server_bin entry create \
    -spiffeID "$gateway_spiffe_id" \
    -parentID "$agent_spiffe_id" \
    -selector "k8s:ns:${gateway_namespace}" \
    -selector "k8s:sa:${gateway_service_account}"
fi
spire_server_bin entry show -spiffeID "$gateway_spiffe_id"

echo
echo "== building the gateway image (cross-compiled linux/amd64, no registry) =="
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

echo "-- compiling cmd/gateway and cmd/gateway-verify for linux/amd64 --"
# Cross-compiled from the host rather than built inside the Docker image:
# this repo's go.sum already has everything these binaries need in the
# local module cache (from `go build ./...` during development), so this
# avoids a `go mod download` step inside the image build needing network
# access, and keeps the Docker build itself trivial (see
# deploy/gateway/Dockerfile).
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${work_dir}/gateway" ./cmd/gateway
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${work_dir}/gateway-verify" ./cmd/gateway-verify

echo "-- docker build =="
docker build -t "$image_name" -f deploy/gateway/Dockerfile "$work_dir"

echo "-- k3d image import (loads the image straight into the cluster's containerd, no registry) =="
k3d image import "$image_name" -c "$cluster_name"

echo
echo "== installing the gateway (helm, this repo's own chart: ${chart_dir}) =="
helm upgrade --install gateway "$chart_dir" \
  --kube-context "$kube_context" \
  --namespace "$gateway_namespace" --create-namespace \
  -f "$values_file" \
  --wait --timeout 120s

echo
echo "== waiting for the gateway pod to be ready =="
kctl -n "$gateway_namespace" rollout status deployment/gateway --timeout=120s

echo
echo "== running the live verification job (deploy/gateway/verify-job.yaml) =="
# Delete-then-apply rather than relying on Job immutability semantics --
# this script is meant to be re-run, and a Job whose spec never changes but
# whose underlying image (":dev", re-imported above) did would otherwise
# leave a stale completed/failed Job sitting there instead of actually
# re-verifying anything.
kctl -n "$sample_namespace" delete job gateway-verify --ignore-not-found >/dev/null
kctl apply -f "$verify_job_manifest"

echo "-- waiting for the verification job to finish (up to 60s) --"
# `kubectl wait --for=condition=complete` alone would hang forever on a
# failed Job (condition=complete never becomes true), so wait on either
# outcome and inspect which one actually happened afterwards.
kctl -n "$sample_namespace" wait --for=condition=complete --timeout=60s job/gateway-verify 2>/dev/null || true
kctl -n "$sample_namespace" wait --for=condition=failed --timeout=5s job/gateway-verify 2>/dev/null || true

echo
echo "--- gateway-verify job output ---"
verify_pod="$(kctl -n "$sample_namespace" get pod -l job-name=gateway-verify -o jsonpath='{.items[0].metadata.name}')"
kctl -n "$sample_namespace" logs "$verify_pod"
echo "--- end job output ---"

echo
echo "--- gateway's own log (server-side view of the same accept/reject decisions) ---"
gateway_pod="$(kctl -n "$gateway_namespace" get pod -l app=gateway -o jsonpath='{.items[0].metadata.name}')"
kctl -n "$gateway_namespace" logs "$gateway_pod"
echo "--- end gateway log ---"

job_succeeded="$(kctl -n "$sample_namespace" get job gateway-verify -o jsonpath='{.status.succeeded}')"
echo
if [ "$job_succeeded" = "1" ]; then
  echo "== done: gateway-verify PASSED -- valid SPIFFE peer accepted and correctly identified, invalid peers rejected =="
else
  echo "== FAILED: gateway-verify job did not complete successfully -- see job output above =="
  exit 1
fi

echo "Gateway SPIFFE ID: $gateway_spiffe_id"
echo "Re-run just the verification with:"
echo "  kubectl --context $kube_context -n $sample_namespace delete job gateway-verify --ignore-not-found && kubectl --context $kube_context apply -f $verify_job_manifest"
echo "Tear down the cluster entirely with: k3d cluster delete $cluster_name"
