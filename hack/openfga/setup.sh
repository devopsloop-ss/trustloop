#!/usr/bin/env bash
# Brings up OpenFGA on a local k3d cluster via Helm, loads the TrustLoop
# Phase 0 authorization model, writes test tuples, and runs verification
# checks against it.
#
# This is the one documented, repeatable path referenced by ROADMAP.md
# Phase 0 -- "OpenFGA running locally... installed via helm install, not
# hand-rolled install scripts... Done when the model is loaded and you've
# verified it behaves correctly." Nothing here is a one-off command typed
# into a terminal and forgotten: run this script any time (fresh clone,
# after a reboot, in CI) and it gets you to the same verified state.
#
# Per trustloop/CLAUDE.md: Helm, not docker-compose or hand-rolled install
# scripts, for anything cluster-deployed. This script's job is orchestrating
# k3d + helm + kubectl -- it does not reimplement what any of those tools
# already do.
#
# Usage: hack/openfga/setup.sh
#   (run from anywhere -- it cd's to the repo root itself)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

cluster_name="trustloop-dev"
# k3d's default k3s image (whatever the installed k3d version currently
# resolves as "latest") has been observed to crash-loop on startup in this
# environment shortly after the API server comes up (etcd/kine context
# canceled seconds in) -- while the older v1.30.6-k3s1 used by Topoloop's
# cluster is stable. Pin to that same known-good version rather than
# "latest": it's also the same version ROADMAP.md's "matching Topoloop's
# local target" already asks for, so this isn't a workaround bolted on top
# of the goal, it *is* the goal.
k3s_image="rancher/k3s:v1.30.6-k3s1"

chart_repo_url="https://openfga.github.io/helm-charts"
chart_ref="openfga/openfga"
# Pinned, not "latest" -- see deploy/openfga/values.yaml for why a chart
# bump silently changing defaults (replica count, datastore engine) matters
# enough to guard against.
chart_version="0.3.10"
release_name="openfga"
namespace="openfga"
values_file="deploy/openfga/values.yaml"

echo "== ensuring k3d cluster '$cluster_name' exists =="
if k3d cluster list -o json | grep -q "\"name\":\"${cluster_name}\""; then
  echo "cluster '$cluster_name' already exists -- reusing it"
else
  k3d cluster create "$cluster_name" --image "$k3s_image" --wait --timeout 180s
fi
kubectl config use-context "k3d-${cluster_name}" >/dev/null

echo
echo "== installing OpenFGA (helm, chart ${chart_ref}@${chart_version}) =="
helm repo add openfga "$chart_repo_url" >/dev/null 2>&1 || true
helm repo update openfga >/dev/null
helm upgrade --install "$release_name" "$chart_ref" \
  --version "$chart_version" \
  --namespace "$namespace" --create-namespace \
  -f "$values_file" \
  --wait --timeout 180s

echo
echo "== waiting for OpenFGA pod readiness =="
kubectl -n "$namespace" wait --for=condition=ready pod \
  -l "app.kubernetes.io/instance=${release_name}" --timeout=120s

echo
echo "== port-forwarding OpenFGA HTTP API to localhost:8080 =="
# Run the port-forward in the background for the duration of this script.
# It's intentionally left running after setup.sh exits (see trap below) --
# cmd/openfga-verify (and anyone poking at the API by hand afterwards) needs
# a live localhost:8080 to talk to, same as the old docker-compose setup
# gave for free via published container ports.
kubectl -n "$namespace" port-forward "svc/${release_name}" 8080:8080 8081:8081 3000:3000 \
  >/tmp/trustloop-openfga-port-forward.log 2>&1 &
pf_pid=$!

cleanup_on_failure() {
  echo "setup failed -- stopping port-forward (pid $pf_pid)" >&2
  kill "$pf_pid" 2>/dev/null || true
}
trap cleanup_on_failure ERR

echo "  port-forward pid: $pf_pid (logs: /tmp/trustloop-openfga-port-forward.log)"
for i in $(seq 1 15); do
  if curl -sf http://localhost:8080/healthz >/dev/null 2>&1; then
    break
  fi
  if [ "$i" = "15" ]; then
    echo "OpenFGA API did not become reachable via port-forward in time" >&2
    exit 1
  fi
  sleep 1
done

trap - ERR

echo
echo "== writing model + test tuples, then verifying checks =="
go run ./cmd/openfga-verify

echo
echo "== done =="
echo "OpenFGA HTTP API:  http://localhost:8080"
echo "OpenFGA Playground: http://localhost:3000/playground"
echo "Port-forward is still running in the background (pid $pf_pid)."
echo "Stop it with: kill $pf_pid"
echo "Tear down the cluster entirely with: k3d cluster delete $cluster_name"
