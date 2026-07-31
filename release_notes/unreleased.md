**Unreleased**

* Fail closed on ambiguous endpoint identities and poll authoritative sensor state before confirming isolation changes.
* Enforce cumulative alert row and response-byte budgets before retaining paginated results.
* Isolate per-alert ingestion failures and derive durable checkpoints from successfully saved provider timestamps.
* Require a unique sensor ID for IP-based containment to prevent stale adapter records from selecting an endpoint.
