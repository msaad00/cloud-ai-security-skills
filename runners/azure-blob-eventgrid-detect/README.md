# azure-blob-eventgrid-detect

Reference persistent runner template for Azure Blob Storage event-driven ingest
and detection pipelines.

## Flow

```text
Blob create
  -> Event Grid subscription
  -> ingest queue
  -> ingest handler
  -> detect queue
  -> detect handler
  -> Table Storage dedupe
  -> Service Bus topic
```

The runner keeps state and side effects at the edges:
- Blob Storage is the raw source
- Event Grid routes blob-created events into the ingest queue
- the ingest handler reads the blob, runs an ingest skill, and enqueues lines
- the detect handler consumes queue messages, runs a detect skill, dedupes on a
  stable UID, and publishes new findings to a topic

The skills remain unchanged and stateless.

## When to use it

- You want a repo-owned Azure persistent runner example beyond IAM departures
- You need a minimal Azure pattern for continuous ingest -> detect with replay
  safety
- You want to wire any compatible `ingest-*` and `detect-*` skill pair into a
  queue-driven loop

## What it does not do

- It is not a generic sink framework for every cloud or SIEM
- It does not provision the compute; [`functionapp/`](functionapp/) is the
  reference Azure Functions binding used for the live deploy proof
- It does not hardcode a specific skill family, sink vendor, or storage format

## Required environment variables

### Ingest handler

- `INGEST_SKILL_CMD`
  Example: `python skills/ingestion/ingest-azure-activity-ocsf/src/ingest.py` (OCSF, the default — detect skills consume OCSF)
- `DETECT_QUEUE_NAME`
- `SERVICE_BUS_FQDN`

### Functions binding (`functionapp/function_app.py`)

- `INGEST_QUEUE_NAME` (queue the ingest trigger listens on)
- `ServiceBusConnection__fullyQualifiedNamespace` (identity-based trigger connection)

### Detect handler

- `DETECT_SKILL_CMD`
  Example: `python skills/detection/detect-azure-open-nsg/src/detect.py`
- `DETECT_QUEUE_NAME`
- `ALERT_TOPIC_NAME`
- `DEDUPE_TABLE_NAME`
- `TABLE_ACCOUNT_URL`
- `DEDUPE_TTL_DAYS`
  Optional dedupe retention window in days. Defaults to `30`. Azure Table
  Storage does not provide native row TTL here, so the handler enforces the
  replay window by treating expired rows as replaceable on the next sighting.
- `SERVICE_BUS_FQDN`

## Packaging model

The template expects the operator to package the queue handlers together with
their Python dependencies and bind them to an Azure runtime of their choice.
The template itself provisions:

- the Event Grid subscription for blob-created events
- an ingest queue
- a detect queue
- a fan-out topic
- a Table Storage account for replay-safe dedupe state

## Concurrency ceiling

The Bicep template exports `recommendedMaxInstances` and defaults it to `50`.
Because this runner intentionally does not provision the Function App or
Container Apps packaging layer, the ceiling is an operator-facing contract: wire
the same value into your chosen Azure runtime so queue-driven scale does not run
unbounded.

## Security model

- no shell invocation; skill commands are tokenized with `shlex.split`
- `subprocess.run(..., shell=False)` only
- Event Grid payloads are treated as untrusted input
- dedupe prevents duplicate publishes on replay
- dedupe rows carry `expires_at`; expired rows are replaced by the handler so
  replay protection stays bounded even though Table Storage does not auto-purge
  them
- detect-side downstream fan-out sends findings to Service Bus in grouped
  batches instead of one API call per finding
- operators should scope the Azure role assignments to the specific blob
  source, queue, topic, and table resources in their environment

## Live Deploy Verification Status

Real deploy proof captured on 2026-10-07 (Azure `eastus2`, Linux Consumption
Function App, Python 3.11, Functions v4) with `ingest-azure-activity-ocsf` →
`detect-azure-open-nsg` and the golden fixture
`skills/detection-engineering/golden/azure_open_nsg_raw.json`, following the
[Prepared Walkthrough](#prepared-walkthrough) below. Everything lived in one
new resource group that was deleted afterwards and verified not-found
(including purging the soft-deleted Log Analytics workspace). Subscription ID
is redacted.

| Step | Evidence |
|---|---|
| deploy | `az deployment group create` → `Succeeded` (Service Bus Standard namespace, 2 queues, topic, dedupe storage, Event Grid system topic + subscription) in ~70 s |
| package / bind | `config-zip --build-remote true` → status 4 (success); `function list` shows `ingest` → `%INGEST_QUEUE_NAME%`, `detect` → `%DETECT_QUEUE_NAME%`; managed identity with 4 data-plane roles scoped to the RG resources |
| trigger | blob `raw/incoming/run3/azure_open_nsg_raw.json` uploaded 04:28:53Z; Event Grid `PublishSuccessCount` = `DeliverySuccessCount` (0 failed, 0 dead-lettered); ingest queue held 1 message until the function drained it |
| ingest | `runner-ingest {"blob_events_processed": 1, "blobs_processed": 1, "messages_enqueued": 1}` — `Executed 'Functions.ingest' (Succeeded, 2290ms)`; bare `python` resolves on the Functions Python 3.11 image |
| detect | `runner-detect {"duplicates": 0, "messages_processed": 1, "published": 1}` — `Executed 'Functions.detect' (Succeeded, 1758ms)` |
| dedupe | Table entity `PartitionKey=finding`, `RowKey=ansg-eda99f5877b6f39e`, `payload_sha256=7dbdda24…9797` (byte-identical to the golden `azure_open_nsg_pipe_findings.ocsf.jsonl` line, MITRE T1190), `expires_at` = seen_at + 30 d |
| publish | topic subscription `alerts-topic/proof-sub` received 1 message, subject `skill-finding:ansg-eda99f5877b6f39e`, body sha256 identical to the dedupe row |
| redelivery | same blob re-uploaded as `incoming/run4-redeliver/…` 04:30:10Z → ingest ran again; `runner-detect {"duplicates": 1, "messages_processed": 1, "published": 0}`; still exactly 1 Table entity (original `seen_at`) and 1 topic message |

Bugs the live run found and this repo now fixes:

- `detect_handler._dedupe_table()` called `TableClient.create_table_if_not_exists()`,
  which does not exist in `azure-data-tables` (the method lives on
  `TableServiceClient` and returns the `TableClient`). Every detect invocation
  failed with `AttributeError` and the message dead-lettered after 5
  deliveries; the in-process CI fake had modeled the wrong method. The handler,
  the e2e harness fake, and a contract test are corrected.
- The `serviceBusNamespaceFqdn` output is the `https://…:443/` endpoint URL,
  not an FQDN; the new `serviceBusFullyQualifiedNamespace` output returns the
  bare host (verified on the live deployment).

## First Event Proof Checklist

When capturing the live walkthrough for this runner, record:

1. the exact Bicep deployment inputs and provisioned resources
2. the chosen Azure runtime packaging path for the handlers
3. one blob created in the watched source path
4. evidence that:
   - Event Grid routed the event
   - ingest queue received the message
   - ingest handler ran and enqueued detect work
   - detect handler ran
   - Table Storage dedupe wrote a stable UID row
   - Service Bus topic publish succeeded

## Prepared Walkthrough

The template provisions the event path and state, not the compute. The
reference compute binding is [`functionapp/`](functionapp/): an Azure
Functions (Python v2 model) `function_app.py` with one Service Bus trigger per
queue, `host.json`, and `requirements.txt`. Both triggers use the managed
identity through `ServiceBusConnection__fullyQualifiedNamespace`, so no
connection string is stored.

### 1. Deploy the infrastructure

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file runners/azure-blob-eventgrid-detect/template.bicep \
  --parameters \
      sourceStorageAccountName=<existing-source-storage-account> \
      sourceContainerName=<existing-source-container> \
      serviceBusNamespaceName=<service-bus-namespace> \
      dedupeStorageAccountName=<dedupe-storage-account>
```

Service Bus rejects namespace names ending in `-sb` (reserved suffix).
Use the `serviceBusFullyQualifiedNamespace` output (bare host) wherever an
FQDN is required; `serviceBusNamespaceFqdn` is the `https://…:443/` endpoint URL.

### 2. Bind the handler runtime (Function App)

```bash
az functionapp create -g <resource-group> -n <function-app> \
  --storage-account <dedupe-storage-account> \
  --consumption-plan-location <region> --os-type Linux \
  --runtime python --runtime-version 3.11 --functions-version 4 \
  --assign-identity '[system]' --app-insights <app-insights-name>

PRINCIPAL=$(az functionapp identity show -g <resource-group> -n <function-app> --query principalId -o tsv)
az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Reader" --scope <source-storage-account-id>
az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "Azure Service Bus Data Receiver" --scope <service-bus-namespace-id>
az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "Azure Service Bus Data Sender" --scope <service-bus-namespace-id>
az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "Storage Table Data Contributor" --scope <dedupe-storage-account-id>

SB=<serviceBusFullyQualifiedNamespace output>
az functionapp config appsettings set -g <resource-group> -n <function-app> --settings \
  "ServiceBusConnection__fullyQualifiedNamespace=$SB" "SERVICE_BUS_FQDN=$SB" \
  INGEST_QUEUE_NAME=ingest-queue DETECT_QUEUE_NAME=detect-queue ALERT_TOPIC_NAME=alerts-topic \
  DEDUPE_TABLE_NAME=runnerdedupe TABLE_ACCOUNT_URL=https://<dedupe-storage-account>.table.core.windows.net \
  "INGEST_SKILL_CMD=python skills/ingestion/ingest-azure-activity-ocsf/src/ingest.py" \
  "DETECT_SKILL_CMD=python skills/detection/detect-azure-open-nsg/src/detect.py" \
  SCM_DO_BUILD_DURING_DEPLOYMENT=true
```

Package the handlers, the Functions binding, `skills/_shared`, and the two
skill directories (repo layout preserved), then zip-deploy with a remote build
so the Azure SDK dependencies are installed on the platform. From the repo root:

```bash
zip -qr -X /tmp/azure-func.zip skills/_shared \
  skills/ingestion/ingest-azure-activity-ocsf/src skills/detection/detect-azure-open-nsg/src -x '*__pycache__*'
(cd runners/azure-blob-eventgrid-detect && zip -q -j -X /tmp/azure-func.zip \
  src/ingest_handler.py src/detect_handler.py \
  functionapp/function_app.py functionapp/host.json functionapp/requirements.txt)
az functionapp deployment source config-zip -g <resource-group> -n <function-app> \
  --src /tmp/azure-func.zip --build-remote true
az functionapp restart -g <resource-group> -n <function-app>
```

On Linux Consumption a redeploy was observed to keep serving the previous
package until the app was restarted; restart after every redeploy.

### 3. Send one real event

```bash
az storage blob upload \
  --account-name <existing-source-storage-account> \
  --container-name <existing-source-container> \
  --name incoming/azure_open_nsg_raw.json \
  --file skills/detection-engineering/golden/azure_open_nsg_raw.json
```

### 4. Capture proof

- Event Grid delivery evidence for the blob-created event
- a message in the ingest queue
- runtime logs for the ingest handler
- a message in the detect queue
- runtime logs for the detect handler
- a Table Storage entity with `PartitionKey`, `RowKey`, `payload_sha256`, and `expires_at`
- a Service Bus topic message or downstream subscriber receipt
