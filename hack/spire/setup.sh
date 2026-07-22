#!/usr/bin/env bash
# Brings up SPIRE (server + agent) on a local k3d cluster via Helm, creates
# a registration entry for a sample workload using the K8s workload attestor
# (namespace/service-account selectors, not a hand-typed workload ID), and
# verifies -- for real, not just "helm install succeeded" -- that the sample
# workload actually receives a SPIRE-issued SVID: both server-side
# (`spire-server entry show`) and client-side (the workload's own copy of
# the issued certificate, fetched via the real Workload API).
#
# This is the one documented, repeatable path referenced by ROADMAP.md
# Phase 0 -- "SPIRE server + agent running locally... installed via the
# official spiffe/spire Helm chart, issuing SVIDs to sample workloads
# automatically." Nothing here is a one-off command typed into a terminal
# and forgotten: run this script any time (fresh clone, after a reboot, in
# CI) and it gets you to the same verified state.
#
# Per trustloop/CLAUDE.md: Helm, not hand-rolled install scripts, for
# anything cluster-deployed. This script's job is orchestrating
# k3d + helm + kubectl -- SPIRE server/agent themselves come entirely from
# the official chart; this script only configures them (see
# deploy/spire/values.yaml) and writes one registration entry, the same way
# hack/openfga/setup.sh writes tuples into an already-Helm-installed OpenFGA
# rather than reimplementing any part of it.
#
# Every kubectl/helm call below pins --context/--kube-context explicitly
# (rather than relying on `kubectl config use-context` + ambient state).
# This workspace commonly has more than one k3d cluster around (e.g.
# Topoloop's), and the current-context is shared, mutable, host-wide state
# -- something else on the machine changing it between two commands in this
# script would otherwise silently point a later command (e.g. `helm
# install`) at the wrong cluster. Explicit --context makes that impossible
# instead of just unlikely.
#
# Usage: hack/spire/setup.sh
#   (run from anywhere -- it cd's to the repo root itself)
set -euo pipefail

# On Windows/Git Bash, MSYS rewrites anything that looks like a Unix
# absolute path (e.g. /opt/spire/bin/spire-server) into a Windows path
# *before* it ever reaches kubectl -- which is correct for local file
# arguments, but wrong here: these are paths *inside a Linux container*,
# which MSYS has no way to know. Without this, `kubectl exec ... --
# /opt/spire/bin/spire-server` silently becomes `kubectl exec ... --
# C:/Program Files/Git/opt/spire/bin/spire-server` and fails confusingly.
# No-op on Linux/macOS.
export MSYS_NO_PATHCONV=1

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

cluster_name="trustloop-dev"
kube_context="k3d-${cluster_name}"
# Same pin, same reason as hack/openfga/setup.sh: k3d's default/"latest" k3s
# image has been observed to crash-loop on startup on this machine's Docker
# Desktop/WSL2 backend; this older version is stable. Also matches
# Topoloop's local dev target, per ROADMAP.md.
k3s_image="rancher/k3s:v1.30.6-k3s1"

chart_repo_url="https://spiffe.github.io/helm-charts-hardened/"
chart_repo="spire"
# Pinned, not "latest" -- see deploy/spire/values.yaml for why a chart bump
# silently changing defaults (which sub-components run, node/workload
# attestor config) matters enough to guard against. 0.29.0 is spire-server/
# spire-agent app version v1.15.1 (also the version the sample workload's
# spire-agent CLI image is pinned to -- see deploy/spire/sample-workload.yaml
# -- so the client CLI and server/agent are always the same SPIRE release).
crds_chart_version="0.5.0"
chart_version="0.29.0"
release_name="spire"
crds_release_name="spire-crds"
# Everything (server, agent, CSI driver) lands in one namespace -- the Helm
# release's own namespace -- unless global.spire.recommendations.enabled +
# namespaceLayout opt into the chart's split-namespace layout, which
# deploy/spire/values.yaml deliberately doesn't (see its comments). spire-crds
# only contains cluster-scoped CustomResourceDefinition objects, so it
# doesn't need this namespace to exist at all -- park its release metadata
# in "default" instead of fighting the "spire" release for ownership of a
# namespace it doesn't use (see deploy/spire/values.yaml's
# global.spire.namespaces.create comment for the full story).
crds_release_namespace="default"
release_namespace="spire-server"
values_file="deploy/spire/values.yaml"
sample_workload_manifest="deploy/spire/sample-workload.yaml"

trust_domain="trustloop-dev.local"
sample_namespace="trustloop-sample"
sample_service_account="sample-workload"
sample_spiffe_id="spiffe://${trust_domain}/ns/${sample_namespace}/sa/${sample_service_account}"

kctl() { kubectl --context "$kube_context" "$@"; }

echo "== ensuring k3d cluster '$cluster_name' exists =="
if k3d cluster list -o json | grep -q "\"name\":\"${cluster_name}\""; then
  echo "cluster '$cluster_name' already exists -- reusing it"
else
  k3d cluster create "$cluster_name" --image "$k3s_image" --wait --timeout 180s
fi
# Sanity-check the context k3d registered actually points at this cluster,
# rather than assuming the name convention held.
kctl cluster-info >/dev/null

echo
echo "== ensuring the SPIRE namespace exists =="
# Plain kubectl, not chart-templated or --create-namespace -- see
# deploy/spire/values.yaml's global.spire.namespaces.create comment for why:
# Helm's own namespace-creation paths leave ownership metadata in a state
# that makes a second Helm release (or the same chart's own template)
# unable to adopt the namespace afterwards. Idempotent via apply.
kctl create namespace "$release_namespace" --dry-run=client -o yaml | kctl apply -f - >/dev/null

echo
echo "== installing SPIRE CRDs (helm, chart ${chart_repo}/spire-crds@${crds_chart_version}) =="
helm repo add "$chart_repo" "$chart_repo_url" >/dev/null 2>&1 || true
helm repo update "$chart_repo" >/dev/null
helm upgrade --install "$crds_release_name" "${chart_repo}/spire-crds" \
  --kube-context "$kube_context" \
  --version "$crds_chart_version" \
  --namespace "$crds_release_namespace" \
  --wait --timeout 180s

echo
echo "== installing SPIRE server + agent (helm, chart ${chart_repo}/spire@${chart_version}) =="
helm upgrade --install "$release_name" "${chart_repo}/spire" \
  --kube-context "$kube_context" \
  --version "$chart_version" \
  --namespace "$release_namespace" \
  -f "$values_file" \
  --wait --timeout 300s

echo
echo "== waiting for SPIRE server + agent pod readiness =="
kctl -n spire-server wait --for=condition=ready pod \
  -l "app.kubernetes.io/name=server" --timeout=180s
kctl -n spire-server wait --for=condition=ready pod \
  -l "app.kubernetes.io/name=agent" --timeout=180s

spire_server_pod="$(kctl -n spire-server get pod -l app.kubernetes.io/name=server -o jsonpath='{.items[0].metadata.name}')"
spire_server_bin() {
  kctl -n spire-server exec "$spire_server_pod" -- /opt/spire/bin/spire-server "$@"
}

echo
echo "== waiting for the spire-agent to attest to the server =="
# The agent proves its own identity via the K8s node attestor (PSAT) before
# it can do anything else -- including attesting workloads. Until it shows
# up in `spire-server agent list`, no workload on its node can be attested
# either, so this is worth waiting on and checking explicitly rather than
# assuming "the pod is Running" is the same thing as "it's a trusted member
# of the trust domain".
for i in $(seq 1 30); do
  if spire_server_bin agent list | grep -q "SPIFFE ID"; then
    break
  fi
  if [ "$i" = "30" ]; then
    echo "spire-agent never registered itself with spire-server (check: kubectl --context $kube_context -n spire-server logs daemonset/spire-agent)" >&2
    exit 1
  fi
  sleep 2
done
echo "agent(s) attested:"
spire_server_bin agent list

echo
echo "== creating the sample namespace/service account (kubectl apply, not part of any Helm release) =="
kctl apply -f "$sample_workload_manifest"

echo
echo "== creating the registration entry for the sample workload =="
# This is the piece the ticket is actually about: a registration entry whose
# selectors are k8s:ns/k8s:sa -- i.e. "any pod running as this
# namespace+service-account", evaluated dynamically by the K8s workload
# attestor at the moment a workload connects to the agent -- not a
# hand-typed, single-instance workload identifier (e.g. a literal pod UID or
# unix:uid selector looked up by hand). Any pod in trustloop-sample running
# as the sample-workload service account will match this entry and get
# issued sample_spiffe_id automatically, including if it's deleted and
# recreated -- that's the whole point of attestation-by-selector over
# hand-copying certs.
#
# -parentID pins the entry to *this* node's already-attested agent (the one
# confirmed above) -- required by SPIRE so it knows which agent(s) are
# allowed to serve this entry to workloads on their node. We look the
# agent's own SPIFFE ID up live, from `agent list` output, rather than
# hand-typing a node identifier that would drift the moment k3d recreates
# the node.
agent_spiffe_id="$(spire_server_bin agent list | grep 'SPIFFE ID' | head -1 | sed -E 's/^SPIFFE ID\s*:\s*//')"
if [ -z "$agent_spiffe_id" ]; then
  echo "could not determine the attested agent's SPIFFE ID from 'spire-server agent list'" >&2
  exit 1
fi
echo "parent (agent) SPIFFE ID: $agent_spiffe_id"

if spire_server_bin entry show -spiffeID "$sample_spiffe_id" | grep -q "Entry ID"; then
  echo "registration entry for $sample_spiffe_id already exists -- leaving it as-is"
else
  spire_server_bin entry create \
    -spiffeID "$sample_spiffe_id" \
    -parentID "$agent_spiffe_id" \
    -selector "k8s:ns:${sample_namespace}" \
    -selector "k8s:sa:${sample_service_account}"
fi

echo
echo "== waiting for the sample workload pod to be ready =="
kctl -n "$sample_namespace" rollout status deployment/sample-workload --timeout=120s

echo
echo "== verifying (server side): the registration entry exists as created =="
spire_server_bin entry show -spiffeID "$sample_spiffe_id"

echo
echo "== verifying (workload side): the sample pod actually holds an issued SVID =="
sample_pod="$(kctl -n "$sample_namespace" get pod -l app=sample-workload -o jsonpath='{.items[0].metadata.name}')"

echo "--- fetch-svid init container log (one-shot Workload API fetch from inside the pod) ---"
kctl -n "$sample_namespace" logs "$sample_pod" -c fetch-svid

echo
echo "--- pulling the issued certificate itself out of the pod for inspection ---"
work_dir="$(mktemp -d)"
# `kubectl cp` shells out to `tar` inside the target container -- the
# spire-agent containers are scratch-based with no shell/tar (that's
# deliberate, see deploy/spire/sample-workload.yaml), so this reads the file
# via the "holder" busybox sidecar instead. It shares the same emptyDir the
# spire-agent CLI wrote the SVID into and never touches the identity path.
kctl -n "$sample_namespace" cp "${sample_pod}:/svid/svid.0.pem" "${work_dir}/svid.0.pem" -c holder
echo "certificate as seen ON THE WORKLOAD (not the server):"
openssl x509 -in "${work_dir}/svid.0.pem" -noout -subject -issuer -dates -ext subjectAltName
rm -rf "$work_dir"

echo
echo "== done =="
echo "SPIRE trust domain: $trust_domain"
echo "Sample workload SPIFFE ID: $sample_spiffe_id"
echo "Re-inspect any time with:"
echo "  kubectl --context $kube_context -n spire-server exec $spire_server_pod -- /opt/spire/bin/spire-server entry show -spiffeID $sample_spiffe_id"
echo "  kubectl --context $kube_context -n $sample_namespace logs deploy/sample-workload -c watch-svid"
echo "Tear down the cluster entirely with: k3d cluster delete $cluster_name"
