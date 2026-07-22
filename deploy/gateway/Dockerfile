# Container image for the TrustLoop gateway scaffold (issue #3).
#
# Per trustloop/CLAUDE.md: "later this repo's own gateway all get installed
# via their official Helm chart (or ours, if none exists) into the local
# cluster -- from day one." This is that first "ours" -- deploy/gateway/chart
# installs the image this Dockerfile builds. There is no official upstream
# chart/image for TrustLoop's own gateway (it's this repo's product), so
# unlike SPIRE/OpenFGA this is code we own end-to-end -- which is exactly
# why it's still Helm-deployed rather than hand-rolled kubectl, matching the
# same rule that applies to the third-party engines.
#
# The binary is built OUTSIDE this Dockerfile (see hack/gateway/setup.sh,
# which cross-compiles ./cmd/gateway and ./cmd/gateway-verify for
# linux/amd64 using the exact same Go toolchain/go.sum this repo already
# pins) and copied in here. That keeps this image's own build fully
# offline/reproducible (no `go mod download` inside the image build, no
# dependency on the Go base image's toolchain version matching go.mod) and
# mirrors the "helm installs the bare engine; a thin, reviewable
# script/program owns the rest" split already used for OpenFGA and SPIRE.
FROM gcr.io/distroless/static-debian12:nonroot

# Both binaries land in the same image: `gateway` is the actual product
# (what the Helm-deployed Deployment runs); `gateway-verify` is the
# verification client used by hack/gateway/setup.sh's Job (see
# deploy/gateway/verify-job.yaml) to prove the accept/reject paths against
# the live gateway from inside the cluster, where the SPIFFE Workload API
# socket is actually reachable. Shipping them in one image avoids a second
# Dockerfile/build/import round-trip for what is, for this ticket, a
# throwaway verification tool -- not because gateway-verify is meant to run
# as part of the product in later tickets.
COPY gateway /usr/local/bin/gateway
COPY gateway-verify /usr/local/bin/gateway-verify

ENTRYPOINT ["/usr/local/bin/gateway"]
