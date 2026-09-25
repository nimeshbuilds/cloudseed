#!/usr/bin/env bash
# Scenario 07 - Data and AI stack (docs/scenarios/07-data-and-ai-stack.md)
# Default: isolated; every item is planned offline and the Databricks / Snowflake profiles are saved (their connection
# tests need real workspaces). CLOUDSEED_LIVE=1: installs MinIO, CloudNativePG + a Postgres cluster, Ollama and
# Open WebUI on vmware-lab, then uninstalls them. The optional Kafka step is not run.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
scn_begin 07-data-and-ai-stack "Data and AI stack" vmware
need python3 terraform go

step "Before you start: the scenario 05 cluster"
if [[ "$SCN_LIVE" == "1" ]]; then
  lab_cluster
else
  ok cs setup vmware -y --env lab --var enable_kubernetes=true --dry-run
  ok cs env use vmware-lab
fi

step "1. See what the groups bring"
ok cs platform info data
has "cloudnative-pg"
ok cs platform info ai
has "ollama"
ok cs platform info agentic
has "open-webui"
ok cs explain platform ollama
has "otwld"

step "2. Plan the items"
ok cs platform plan minio cloudnative-pg ollama open-webui
has "minio +install"
has "open-webui +install"
has "local-path-provisioner"

step "3. Object storage and Postgres"
cat > demo-pg.yaml <<'YAML'
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: demo-pg
  namespace: data
spec:
  instances: 1
  storage:
    size: 1Gi
YAML
if live "cs platform install minio --set persistence.size=10Gi / cloudnative-pg / a Postgres cluster"; then
  ok cs -y platform install minio --set persistence.size=10Gi --auto-approve
  has "minio installed"
  ok cs -y platform install cloudnative-pg --auto-approve
  ok cs kubectl create namespace data
  ok cs kubectl apply -f demo-pg.yaml
  ok cs kubectl -n data wait cluster/demo-pg --for=condition=Ready --timeout=300s
  ok cs kubectl -n data get cluster demo-pg
  has "Cluster in healthy state"
else
  rc 1 cs -y platform install minio --set persistence.size=10Gi --auto-approve
  has "no Kubernetes cluster yet"
fi

step "4. A dev Kafka cluster (optional)"
skip "cs platform install strimzi (optional, ~2 GB more node memory)"

step "5. A local LLM with a chat UI"
if live "cs platform install ollama open-webui / ollama pull qwen2.5:0.5b / cs platform ui"; then
  ok cs -y platform install ollama open-webui --auto-approve
  ok cs kubectl -n ollama exec deploy/ollama -- ollama pull qwen2.5:0.5b
  ok cs kubectl -n ollama exec deploy/ollama -- ollama list
  has "qwen2.5:0.5b"
  ok cs -y platform ui --auto-approve
  has "https://open-webui\.vmware-lab\.local"
else
  rc 1 cs -y platform install ollama open-webui --auto-approve
fi

step "6. Uninstall what you no longer need"
if live "cs platform uninstall open-webui ollama"; then
  ok cs -y platform uninstall open-webui ollama --auto-approve
  ok cs platform status
  has "minio"
  hasnt "open-webui +deployed"
else
  rc 1 cs -y platform uninstall open-webui ollama --auto-approve
fi

step "7. Managed data platforms"
any cs databricks connect host=https://dbc-1234abcd-5678.cloud.databricks.com
has "Databricks profile '[a-z0-9-]+' saved|cloudseed install databricks"
any cs snowflake connect --account myorg-myaccount --user analyst --warehouse COMPUTE_WH
has "Snowflake profile '[a-z0-9-]+' saved|cloudseed install snow"
any cs databricks test
has "databricks|Databricks"
any cs snowflake test
has "snow|Snowflake"
ok cs snowflake status
has "Managed data platforms"
has "profiles: [a-z]"
skip "cs databricks test / clusters list, cs snowflake test / sql (a real workspace and account)"

step "Verify it worked"
if [[ "$SCN_LIVE" == "1" ]]; then
  ok cs kubectl get pvc -A
  has "demo-pg-1"
fi
ok cs databricks status
has "profiles:"
ok cs explain managed-data
has "Databricks"

step "Clean up"
if [[ "$SCN_LIVE" == "1" ]]; then
  ok cs kubectl delete -f demo-pg.yaml
  ok cs kubectl -n data wait --for=delete cluster/demo-pg --timeout=180s
  ok cs -y platform uninstall cloudnative-pg minio --auto-approve
  ok cs kubectl -n minio delete pvc minio
else
  ok cs destroy vmware -y --env lab --purge --auto-approve
  ok cs env clear
fi
