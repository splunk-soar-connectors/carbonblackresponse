**Unreleased**

* Fail closed on ambiguous endpoint identities and poll authoritative sensor state before confirming isolation changes.
* Enforce cumulative alert row and response-byte budgets before retaining paginated results.
* Isolate per-alert ingestion failures and derive durable checkpoints from successfully saved provider timestamps.
* Require a unique sensor ID for IP-based containment to prevent stale adapter records from selecting an endpoint.
* Stream alert responses through the remaining byte budget before JSON materialization.
* Bound alert-page connection, read, and cumulative pagination time.
* Read bounded alert bodies one network chunk at a time so cumulative deadlines remain observable.
* Enforce the same wall-clock deadline while alert response status and headers are received.
* Preserve the prior alert checkpoint whenever any row in a fetched batch fails to ingest.
