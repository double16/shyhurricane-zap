# shyhurricane-zap

OWASP ZAP plugin to forward requests and findings to a [ShyHurricane](https://github.com/double16/shyhurricane) server.

## How to use it

1. Download JAR file from https://github.com/double16/shyhurricane-zap/releases OR
    ```shell
    git clone https://github.com/double16/shyhurricane-zap.git
    cd shyhurricane-burpsuite
    ./gradlew jarZapAddOn
    ls build/zapAddOn
    build/zapAddOn/bin/shyhurricane-zap-alpha-0.1.0.zap
    ```
2. Load into ZAP
3. Configure in Tools → Options → ShyHurricane
   - Server URL: set the ShyHurricane (MCP) server base URL (default `http://localhost:8000`). The extension will call `POST /index` and `POST /findings` on this base.
   - Only in scope: enable to forward only in scope traffic or issues for an in-scope request.
   - Minimum Risk and Confidence
   - HTTP statuses: select any of 2xx, 3xx, 4xx, and 5xx (default: 2xx only). “Select all statuses” selects all four groups; clearing every group stops HTTP traffic forwarding. 1xx responses are always excluded. This filter applies to `/index` traffic only, not scanner findings.
   - Initiators: Proxy, Spider, AJAX Spider, and Client Spider are selected by default. Select other initiators individually or enable “All request initiators” to forward all initiators.
4. Generate data
   - Use ZAP as usual. The extension will:
      - Post eligible HTTP traffic to `{server}/index` after responses arrive.
      - Post eligible scanner issues to `{server}/findings` when they’re reported.
5. Verify
   - Check your ShyHurricane server logs/UI for received entries.

## Send selected items manually

Select one or more items, right-click, and choose **Send to ShyHurricane**. Sending starts immediately using the configured Server URL, without a confirmation or filter dialog.

| Location | What is sent |
| --- | --- |
| Alerts tree | Selected findings to `/findings`, plus their recorded request/response exchanges to `/index`. Selecting a group includes its descendant alerts. |
| Sites tree | The current recorded exchange for each selected node and its descendants, sent to `/index`. Earlier versions of a node's exchange are not included. |
| History and Request/Response viewers | Selected recorded exchanges to `/index`. |
| Search, Active Scan, Spider, Fuzzer, Forced Browse, and compatible add-on views | Selected exchanges to `/index`, wherever the view exposes ZAP's standard HTTP-message context menu. |

Manual sending ignores all automatic forwarding filters: scope, risk, confidence, initiator, HTTP status, and content type. It also ignores automatic alert duplicate suppression, so you can intentionally send an item again. Overlapping selections and shared alert exchanges are sent only once within a single action; distinct findings are retained.

Only recorded exchanges with a request and response are sent. Requests without a response, missing stored messages, and alerts without an exchange are reported as skipped exchanges; their findings are still sent. The extension never replays requests against the target.

Sending runs in the background. The Output tab reports counts of sent findings, sent exchanges, skipped exchanges, and failures. A single warning appears for a partial or failed batch. Individual failures do not stop the remaining items, and failed posts are not retried automatically. Check the configured Server URL and server availability before selecting failed items to send again.

The sender processes one manual batch at a time and holds up to 16 pending batches. If busy, it reports that the new selection was not queued so you can try again later. Connections time out after 5 seconds and response reads after 15 seconds. Unloading the extension stops the sender and clears pending batches.

## Finding metadata

Automatic and manual `/findings` submissions retain their target URL (including exact query values and escaping), title, and Markdown, and include structured `metadata`:

| Field | Mapping |
| --- | --- |
| `source`, `rule_id` | `zap` and the plugin ID as a string. |
| `source_finding_id` | Alert-instance ID as a string; omitted for negative IDs, including the SDK's `-1` sentinel. |
| `severity` | ZAP Informational/Low/Medium/High → `informational`/`low`/`medium`/`high`. |
| `confidence` | Low/Medium/High/Confirmed → `low`/`medium`/`high`/`high`; omitted for false positives. |
| `native_severity`, `native_confidence` | Original SDK labels when available. Unsupported numeric values normalize to `unknown` and omit unavailable native labels. |
| `verification_status` | `false_positive` for False Positive; otherwise `unverified`, including Confirmed. |
| `affected_method` | Uppercase method from the associated HTTP message; omitted when unavailable or blank. Markdown retains its GET fallback. |
| `cwe_ids` | Singleton list of canonical strings for positive CWE IDs, such as `["CWE-79"]`. |
| `vulnerability_types` | CWE-79 → `xss`; CWE-78/89 → `injection`; CWE-918 → `ssrf`. Each mapped type is sent in a singleton list. Other CWEs omit this field; prose is not used to infer it. |
| `parameter.name` | Nonblank alert parameter name; location is omitted. |

For example, a CWE-79 finding for `http://example.com/search?q=test` includes `"cwe_ids": ["CWE-79"]` and `"vulnerability_types": ["xss"]`. Metadata omits unavailable source coordinates, timestamps, capture IDs, and hashes, and copies no request values, bodies, cookies, or authorization data. Existing Markdown details are preserved.

Automatic duplicate suppression compares the rule, name, risk, confidence, alert-instance ID, exact URI, and parameter as separate tuple fields. Distinct alert instances, including instances with different methods, are retained. Repeated identical events are suppressed atomically. Manual selection deduplication and intentional resending remain unchanged.

Delivery happens in the background. Any HTTP 2xx response, including 201, counts as accepted; server processing may continue asynchronously. Failed posts are not retried, including retries without metadata after a server error.

## Development checks

Run `./gradlew spotlessApply test jacocoTestReport jacocoTestCoverageVerification build` before submitting changes. Coverage reports are written to `build/reports/jacoco/test/`; the forwarding and context-menu implementation must maintain at least 80% line and branch coverage per source file.
