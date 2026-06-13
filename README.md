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
   - Initiators: either keep “All request initiators” enabled or uncheck it and select specific initiators that should be forwarded.
4. Generate data
   - Use ZAP as usual. The extension will:
      - Post eligible HTTP traffic to `{server}/index` after responses arrive.
      - Post eligible scanner issues to `{server}/findings` when they’re reported.
5. Verify
   - Check your ShyHurricane server logs/UI for received entries.
