#!/usr/bin/env bash
# Ensures the shared local minikube cluster TrustLoop develops against is up.
#
# Why minikube (Hyper-V driver) and not k3d-on-Docker-Desktop: the original
# Phase 0 setup created a per-repo `trustloop-dev` k3d cluster on Docker
# Desktop, but Docker Desktop's engine proved unreliable on this stack
# (repeated wedging) and was retired on 2026-07-22 — see CLAUDE.md. minikube
# with the Hyper-V driver boots its own small Linux VM with its own
# container runtime inside, so there is no Docker Desktop / WSL2 layer
# involved at all (which also makes the old k3s cgroup-v1 image pin the k3d
# scripts carried obsolete — the minikube VM image controls its own cgroup
# setup). Same migration, same pattern, as topoloop/hack/dev-cluster.sh.
#
# IMPORTANT: this is the *default* minikube profile ("minikube"), SHARED
# between topoloop and trustloop (separated by namespace inside the
# cluster: topoloop owns `argo`; trustloop owns `openfga`, `spire-server`,
# `trustloop-sample`, `trustloop-gateway`), not a per-repo cluster like the
# old `trustloop-dev` k3d one. That's why this script has no delete/teardown
# path — tearing the cluster down would take the other project's environment
# with it. Tear down trustloop's footprint with `helm uninstall`/`kubectl
# delete ns` on trustloop's own namespaces instead (each setup.sh prints
# how), and never touch the `argo` namespace from this repo.
#
# `minikube start` is idempotent: on an already-running cluster it's a cheap
# reconcile/no-op, so re-running this script is always safe. The fast path
# below never even invokes `minikube` when the API server already answers —
# which also means the everyday "cluster is already up" case works for
# shells that can run kubectl but not manage Hyper-V VMs (minikube lifecycle
# commands need Hyper-V Administrators membership; plain kubectl does not).
#
# Usage:
#   hack/dev-cluster.sh            ensure the shared minikube cluster is up
#
# Env overrides:
#   MINIKUBE_HOME     (default on Windows: D:\minikube — the VM image and
#                      profile state live on D: because C: is nearly full;
#                      see CLAUDE.md. Everyone touching this cluster must use
#                      the same MINIKUBE_HOME or minikube won't find the
#                      existing profile and will try to create a new VM.)
#   MINIKUBE_DRIVER   (default: hyperv)
#   MINIKUBE_MEMORY   (default: 6g)
#   MINIKUBE_CPUS     (default: 4)
set -euo pipefail

MINIKUBE_DRIVER="${MINIKUBE_DRIVER:-hyperv}"
MINIKUBE_MEMORY="${MINIKUBE_MEMORY:-6g}"
MINIKUBE_CPUS="${MINIKUBE_CPUS:-4}"

# On Windows the profile lives on D: (see header). Only default this on
# Windows shells (Git Bash reports msys/cygwin) — on Mac/Linux minikube's
# own default (~/.minikube) is fine and a D:\ path would be nonsense.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    export MINIKUBE_HOME="${MINIKUBE_HOME:-D:\\minikube}"
    ;;
esac

log() { echo "[dev-cluster] $*"; }

require() {
  # Fail fast with a clear message instead of a confusing downstream error
  # if a prerequisite tool isn't on PATH.
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[dev-cluster] required tool '$1' not found on PATH" >&2
    exit 1
  fi
}

require minikube
require kubectl

# Fast path: if the API server already answers on the 'minikube' context,
# the cluster is up — no need to invoke `minikube start` at all.
if kubectl --context minikube cluster-info >/dev/null 2>&1; then
  log "shared minikube cluster is already running — reusing it"
else
  log "starting shared minikube cluster (driver=${MINIKUBE_DRIVER}, memory=${MINIKUBE_MEMORY}, cpus=${MINIKUBE_CPUS}, MINIKUBE_HOME=${MINIKUBE_HOME:-<minikube default>})"
  # --memory/--cpus only apply on first-ever creation of the VM; on an
  # existing profile `minikube start` ignores them and just boots/reconciles
  # what's there (it warns, harmlessly, if they differ).
  minikube start \
    --driver="$MINIKUBE_DRIVER" \
    --memory="$MINIKUBE_MEMORY" \
    --cpus="$MINIKUBE_CPUS"
fi

# `minikube start` already writes the kubeconfig entry and switches the
# current context, but the fast path above doesn't — make it explicit and
# idempotent for both branches. (trustloop's setup scripts pin --context
# minikube on every call anyway; this just keeps ad-hoc kubectl afterwards
# pointed at the right cluster too.)
kubectl config use-context minikube >/dev/null

log "waiting for node to report Ready"
kubectl --context minikube wait --for=condition=Ready node --all --timeout=120s

log "shared minikube cluster is up:"
kubectl --context minikube get nodes -o wide
