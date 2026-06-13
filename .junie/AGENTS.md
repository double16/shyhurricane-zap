## Critical rules the agent must follow before doing anything
- Read `README.md` before acting.
- Update `CHANGELOG.md` for user-facing changes.

## Testing and contribution
- Always write unit tests and check that they pass for new business logic.
- Always run unit tests to verify changes.
- Test both positive and negative scenarios.
- Do not rename files without a valid technical reason.

## Explicit prohibitions what agents must NOT do
- Do not bump major versions of core dependencies without a dedicated PR and discussion.

## Java best practices
- Prefer immutability: use `final` for fields/variables where possible; avoid mutable static state.
- Use meaningful names and small methods; keep classes focused on a single responsibility.
- Null-safety: fail fast with `Objects.requireNonNull` or use `Optional` for truly optional returns; validate public method inputs.
- Concurrency:
  - Avoid shared mutable state; use thread-safe collections and `ConcurrentHashMap` when needed.
  - Guard background threads/services with proper lifecycle management and interruption handling.
- Exceptions:
  - Use checked exceptions for recoverable conditions and unchecked for programmer errors.
  - Do not swallow exceptions; add context and rethrow or handle. Avoid logging and rethrowing without need (double logging).
- Logging:
  - Use a consistent logging facade (e.g., SLF4J) and appropriate levels (`trace`/`debug`/`info`/`warn`/`error`).
  - Never log secrets, API keys, tokens, or PII; redact sensitive data.
- I/O and resources: use try-with-resources; close streams/sockets; set timeouts for network calls.
- Collections: prefer interfaces (`List`, `Map`) in APIs; avoid returning internal mutable collections (return unmodifiable views or copies).
- Equality and hashing: when overriding `equals`, always override `hashCode`; keep them consistent and immutable.
- Testing: write unit tests for business logic; include positive and negative cases; avoid time/date flakiness (use fixed clocks).
- Performance: measure before optimizing; avoid premature micro-optimizations; consider algorithmic complexity.
- Security: validate and sanitize external inputs; use safe defaults; avoid reflection unsafe operations; keep dependencies updated.

## OWASP ZAP plugin (add-on) best practices
- Follow ZAP add-on structure and lifecycle:
  - Extend appropriate extension classes (e.g., `ExtensionAdaptor`) and register via `ExtensionHook`.
  - Keep initialization light; postpone heavy work to background threads, not the EDT (UI thread).
- Respect user scope and configuration:
  - Act only on in-scope targets when applicable; provide options to restrict by context/scope.
  - Honour user settings like minimum risk/confidence, selected initiators, and “only in scope”.
- Threading and listeners:
  - Implement `HttpSenderListener` carefully; avoid blocking in `onHttpRequestSend`/`onHttpResponseReceive`.
  - Offload long-running processing to worker threads/queues; ensure orderly shutdown on unload.
- Memory and resource management:
  - Do not retain `HttpMessage`/`HistoryReference` longer than needed; copy minimal data required.
  - Avoid large in-memory caches; consider bounded queues and back-pressure.
- UI and i18n:
  - Use `OptionsPanel` and `OptionsParam` for user-configurable settings.
  - Externalize strings with `Constant.messages` and provide message bundles for i18n.
- Logging and diagnostics:
  - Use ZAP’s logging conventions; keep logs concise; include correlation identifiers where useful.
  - Do not log full request/response bodies by default; provide opt-in debug if necessary with clear warnings.
- Add-on metadata and dependencies:
  - Keep `zap-add-on.xml` (or equivalent metadata) accurate: name, version, author, description, and dependencies.
  - Avoid bundling conflicting library versions with ZAP core; prefer using ZAP-provided libs or shade carefully with relocation if unavoidable.
- Security considerations:
  - Treat all data from websites under test as untrusted; sanitize before forwarding or persisting.
  - Prevent SSRF and open redirects when the plugin makes outbound calls; validate destinations and enforce allowlists.
  - Do not store secrets in plaintext; use system keychains/secure storage if credentials are required.
- Testing:
  - Provide unit tests for core logic independent of ZAP runtime where possible.
  - For integration behavior, use ZAP’s test frameworks or lightweight fakes/mocks; include both positive and negative paths.
- Unloadability and robustness:
  - Make `canUnload` return true where feasible and implement `unload()` to deregister listeners, stop threads, and release resources.
  - Handle ZAP shutdown gracefully; respond to interrupts and close executors.

