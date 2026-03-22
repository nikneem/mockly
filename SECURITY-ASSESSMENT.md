# Security Assessment — Mockly

**Date:** 2026-03-22  
**Scope:** Full codebase (`Mockly`, `FluentAssertions.Mockly.v7/v8`, CI/CD pipeline)  
**Assessment type:** White-box source-code review  

---

## Executive Summary

Mockly is a **test-only library** that intercepts `HttpClient` traffic inside unit/integration tests. It does **not run in production** and does not expose a network surface on its own. The classical "hacker attacks a running server" threat model therefore does not directly apply. However, the library has several exploitable vulnerabilities that matter in the following realistic threat scenarios:

| Threat scenario | Why it matters |
|---|---|
| A malicious test file or CI/CD pipeline input feeds crafted patterns into Mockly | ReDoS, unbounded memory |
| Mockly is accidentally used (or left enabled) outside of test assemblies | Unbounded resource growth, information disclosure |
| A compromised developer workstation or supply-chain attack targets the CI/CD pipeline | Mutable action tags, over-broad permissions |
| Concurrent test execution with shared `HttpMock` instances | Data races, incorrect mock matching, silent data loss |

The findings are grouped by severity: **Critical → High → Medium → Low → Informational**.

---

## Findings

### CRITICAL-01 — ReDoS in `WithBodyMatchingRegex`

**File:** `Mockly/RequestMockBuilder.cs` (line ~135)  
**File:** `Mockly/Common/StringExtensions.cs` (line ~16)

**Description:**  
`WithBodyMatchingRegex` passes a caller-supplied regex string directly to `Regex.IsMatch` without a timeout:

```csharp
// RequestMockBuilder.cs
return With(request => request.Body is not null && Regex.IsMatch(request.Body, regex), …);

// StringExtensions.cs
return Regex.IsMatch(text, regexPattern, RegexOptions.IgnoreCase);  // no timeout
```

An adversary who controls the regex string (e.g., through test-generation tooling, external configuration, or a crafted test file in a PR) can supply a catastrophically-backtracking pattern such as `(a+)+$` matched against a long body. This will lock a test-runner thread for minutes or indefinitely — effectively a Denial of Service of the build pipeline.

The same issue exists in `StringExtensions.MatchesWildcard`, which converts a wildcard to a regex but then calls `Regex.IsMatch` without `RegexOptions.NonBacktracking` or a `matchTimeout`.

**Recommendation:**  
- Use `Regex.IsMatch(text, pattern, options, matchTimeout: TimeSpan.FromSeconds(1))` everywhere.
- On .NET 7+, use `RegexOptions.NonBacktracking` for all wildcard-derived patterns.
- Validate that regex patterns do not contain dangerous constructs (nested quantifiers) before compiling.

---

### CRITICAL-02 — Unbounded Static Regex Cache (Memory Exhaustion / DoS)

**File:** `Mockly/RequestMock.cs` (line 16)

```csharp
private static readonly ConcurrentDictionary<string, Regex> RegexCache =
    new(StringComparer.OrdinalIgnoreCase);
```

**Description:**  
`RegexCache` is a **static, process-wide, unbounded** dictionary. Every unique pattern that passes through `MatchesPattern` is permanently stored. The cache is never evicted and has no maximum size.

In a large test suite with parameterised tests or dynamically constructed URL patterns this causes unbounded memory growth. More critically, an adversary who can control path/host/query patterns (e.g., through test data files read from disk, or dynamically generated integration test inputs) can deliberately insert thousands of unique patterns to exhaust process memory.

**Recommendation:**  
- Replace `ConcurrentDictionary` with a bounded LRU cache (e.g., backed by `LinkedList<>` + `Dictionary<>` with a capacity cap, or a library like `Microsoft.Extensions.Caching.Memory`).
- Alternatively, store the compiled `Regex` on the `RequestMock` instance itself (instance-level cache) so it is garbage-collected with the mock.

---

### HIGH-01 — Thread-Safety: Race Conditions on `List<RequestMock>`

**File:** `Mockly/HttpMock.cs` (lines 18, 230–233, 363–365)

```csharp
private readonly List<RequestMock> mocks = new();   // not thread-safe

internal void AddMock(RequestMock mock) { mocks.Add(mock); }    // writer
…
RequestMock? matchingMock = await mocks.FirstOrDefaultAsync(…); // reader
```

**Description:**  
`List<T>` is not thread-safe. When `AddMock` is called concurrently with `HandleRequest` (which iterates `mocks`), the list can be in an inconsistent state, causing `IndexOutOfRangeException`, `NullReferenceException`, or silently returning the wrong mock. This is a realistic scenario in parallel test frameworks (e.g., xUnit with `[Collection]` sharing an `HttpMock`).

**Recommendation:**  
Replace `List<RequestMock>` with `System.Collections.Concurrent.ConcurrentBag<T>` or `ImmutableList<T>` with copy-on-write semantics, or protect all access behind a `lock` / `ReaderWriterLockSlim`.

---

### HIGH-02 — Thread-Safety: Race Condition on `InvocationCount` and `IsExhausted`

**File:** `Mockly/RequestMock.cs` (lines 40–52, 253)

```csharp
public int InvocationCount { get; private set; }
…
InvocationCount++;  // non-atomic
```

**Description:**  
`InvocationCount` is incremented with `++` which is **not atomic** on any platform. Under concurrent request processing, two threads can read the same value, both increment it, and write back the same result — so the count is under-counted. More dangerously, `IsExhausted` is checked before `InvocationCount` is incremented (in `TryFindMatchingMock`), creating a **check-then-act** race: two concurrent requests can both observe `IsExhausted == false` and both match the same "Once()" mock, causing it to respond twice.

**Recommendation:**  
Use `Interlocked.Increment(ref _invocationCount)` and store the result to check the limit atomically, or protect the entire "check exhausted → increment → respond" sequence behind a lock.

---

### HIGH-03 — Thread-Safety: Race Condition in `NormalizeHostPatternOnce`

**File:** `Mockly/RequestMock.cs` (lines 134–146)

```csharp
private bool hostPatternNormalized;

private void NormalizeHostPatternOnce()
{
    if (!hostPatternNormalized && HostPattern is not null && HostPattern != "*")
    {
        …
        HostPattern += Scheme!.Equals(…) ? ":443" : ":80";
    }
    hostPatternNormalized = true;
}
```

**Description:**  
The check-then-act is not guarded by a lock. Two concurrent requests calling `Matches()` on the same `RequestMock` can both see `hostPatternNormalized == false`, and both append the port suffix to `HostPattern`, resulting in a pattern like `localhost:443:443` that never matches.

**Recommendation:**  
Use a `lock` or `Lazy<>` to ensure the normalization runs exactly once even under concurrent access.

---

### HIGH-04 — Thread-Safety: `RequestCollection` Not Thread-Safe

**File:** `Mockly/RequestCollection.cs` (lines 13–22)

```csharp
private readonly List<CapturedRequest> requests = new();

internal void Add(CapturedRequest request)
{
    requests.Add(request);
    request.Sequence = requests.Count;  // non-atomic
}
```

**Description:**  
Both `HttpMock.Requests` (shared across all requests) and per-mock `RequestCollection` objects use a plain `List<CapturedRequest>`. Concurrent HTTP request handling can cause data corruption, lost items, or incorrect `Sequence` numbers. The two-step add-then-assign sequence for `Sequence` is also non-atomic.

**Recommendation:**  
Use `ConcurrentQueue<CapturedRequest>` or protect `Add` with a lock. Use `Interlocked.Increment` for the sequence counter.

---

### HIGH-05 — Thread-Safety: `previousBuilder` Shared Mutable State

**File:** `Mockly/HttpMock.cs` (line 19, 49–69, etc.)

```csharp
private RequestMockBuilder? previousBuilder;
```

**Description:**  
Every `ForGet()`, `ForPost()`, etc. call both reads and writes `previousBuilder` without synchronisation. In tests that configure mocks from multiple threads (e.g., test fixtures running in parallel), this causes non-deterministic builder inheritance, where one mock accidentally picks up settings intended for another, or a builder is shared between two concurrent calls.

**Recommendation:**  
Either document that `HttpMock` is not thread-safe for configuration (and is per-test instance only), or use a lock around all `previousBuilder` reads and writes. Consider removing the shared `previousBuilder` pattern entirely.

---

### MEDIUM-01 — Information Disclosure in Exception Messages

**File:** `Mockly/HttpMock.cs` (lines 287–346)

```csharp
messageBuilder.AppendLine($"  {request.Method} {request.Uri} with body of {request.Body?.Length ?? 0} bytes");
…
messageBuilder.AppendLine($"  \"{request.Body}\"");
```

**Description:**  
`ThrowDetailedException` dumps the full request URI **and the full request body** into the `UnexpectedRequestException` message. If the request body contains sensitive data such as API keys, bearer tokens, passwords, or PII (personally identifiable information), this data is:
- Printed to the test runner output
- Included in CI/CD build logs (which may be publicly visible for open-source repos)
- Stored in test result XML files uploaded as build artifacts

The same issue exists in `RequestMock.TrackRequest()`:
```csharp
capturedRequest.Response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
{
    ReasonPhrase = $"{e.GetType().Name}:{e.Message}"
};
```
Exception messages from a responder can disclose internal state.

**Recommendation:**  
- Truncate or redact the body in error messages (e.g., show only the first 200 characters, or replace with `<redacted>` for content types that may carry credentials).
- Do not include the full URI path if it may contain sensitive query parameters (e.g., `?api_key=...`).

---

### MEDIUM-02 — JSON Bomb / Deep-Recursion DoS in `WithBodyMatchingJson`

**File:** `Mockly/RequestMockBuilder.cs` (lines ~148–178)

```csharp
using var actualDocument = JsonDocument.Parse(request.Body);
return expectedRoot.JsonEquals(actualDocument.RootElement);
```

**Description:**  
`JsonDocument.Parse` is called on the raw request body **without `JsonDocumentOptions`**. A crafted JSON payload with extreme nesting depth (e.g., `[[[[[[…]]]]]]` thousands of levels deep) can exhaust the call stack via `JsonElement.Clone()` and the recursive `JsonEquals` method, causing a `StackOverflowException` or extreme memory pressure. `JsonSerializer.Deserialize` has similar exposure.

**Recommendation:**  
Pass `JsonDocumentOptions` with an explicit `MaxDepth`:
```csharp
var options = new JsonDocumentOptions { MaxDepth = 64 };
using var actualDocument = JsonDocument.Parse(request.Body, options);
```
The default .NET limit is 64; explicitly setting it documents intent and future-proofs against any default changes.

---

### MEDIUM-03 — Unbounded Body Prefetch (Memory/DoS)

**File:** `Mockly/HttpMock.cs` (lines 349–358)

```csharp
if (PrefetchBody && httpRequest.Content is not null)
{
    body = await httpRequest.Content.ReadAsStringAsync();
}
```

**Description:**  
The entire request body is read into a `string` without any size limit. While this is a test library, a test that sends large payloads (e.g., file-upload simulation) can exhaust memory. If Mockly is ever used in a shared test server or integration-test host, a malicious caller can send a multi-GB body to cause an `OutOfMemoryException`.

**Recommendation:**  
Add a configurable `MaxBodySize` property (defaulting to, e.g., 10 MB). Read at most that many bytes, and truncate/throw if exceeded.

---

### MEDIUM-04 — CI/CD: Overly Broad GitHub Actions Permissions

**File:** `.github/workflows/build.yml` (lines 11–16)

```yaml
permissions:
  id-token: write
  attestations: write
  contents: write        # ← can write to repo contents
  security-events: write
  actions: write         # ← can modify workflow runs
```

**Description:**  
The build job grants `contents: write` and `actions: write` to **all pushes and pull requests**, including pull requests from forks. A malicious PR could exploit these tokens. The `NugetArtifactsApiKey` secret is also passed as an environment variable to the build step unconditionally:

```yaml
env:
  NugetArtifactsApiKey: ${{ secrets.NUGETAPIKEY }}
```

If a fork PR can exfiltrate environment variables (e.g., via a crafted NUKE build script), the NuGet publish key is compromised.

**Recommendation:**  
- Scope `contents: write` and `actions: write` to the publish step only, guarded by `if: startsWith(github.ref, 'refs/tags/')`.
- Move secret-using steps to a separate job that only runs on protected branches/tags, not on fork PRs.
- Use `github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository` as a condition before exposing secrets.

---

### MEDIUM-05 — CI/CD: Mutable Action References (Supply-Chain Risk)

**File:** `.github/workflows/build.yml`

```yaml
uses: actions/checkout@v6
uses: actions/setup-dotnet@v5
uses: actions/upload-artifact@v7
uses: actions/download-artifact@v8
uses: actions/attest-build-provenance@v4
uses: github/codeql-action/upload-sarif@v4
uses: andstor/file-existence-action@v3
uses: coverallsapp/github-action@v2
uses: EnricoMi/publish-unit-test-result-action@v2
```

**Description:**  
All GitHub Actions are pinned to mutable **tag references** (e.g., `@v6`). A tag can be moved to a different commit at any time. A compromised action maintainer account, or a typosquatted action, could deliver malicious code to the build runner that has access to repository secrets.

**Recommendation:**  
Pin each action to its full commit SHA:
```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```
Use [Dependabot's `commit-hash` pinning](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#versioning-strategy) or a tool like `pinact` to maintain SHA pins automatically.

---

### LOW-01 — Missing `IDisposable` on `HttpMock` and `CapturedRequest`

**File:** `Mockly/HttpMock.cs`, `Mockly/CapturedRequest.cs`

**Description:**  
`GetClient()` creates an `HttpClient` and explicitly suppresses `CA2000` (the warning that the handler is not disposed):

```csharp
#pragma warning disable CA2000
var client = new HttpClient(new MockHttpMessageHandler(this)) { … };
return client;
#pragma warning restore CA2000
```

`CapturedRequest.Response` holds an `HttpResponseMessage` that is never disposed. Over time, in large test suites, this causes native socket/handle leaks on some platforms.

**Recommendation:**  
- Document that callers must `Dispose()` the returned `HttpClient`.
- Implement `IDisposable` on `HttpMock` to dispose all tracked clients/responses.
- Consider making `CapturedRequest` implement `IDisposable` to dispose its `HttpResponseMessage`.

---

### LOW-02 — Exception-Swallowing Masks Serious Failures

**File:** `Mockly/RequestMock.cs` (lines 263–275)

```csharp
#pragma warning disable CA1031
catch (Exception e)
#pragma warning restore CA1031
{
    capturedRequest.Response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
    {
        ReasonPhrase = $"{e.GetType().Name}:{e.Message}"
    };
}
```

**Description:**  
All exceptions thrown by a user-provided `Responder` are silently converted to a 500 response. This includes `StackOverflowException`, `ThreadAbortException`, and programming errors like `NullReferenceException`. Tests that should fail due to a broken responder instead produce unexpected 500 responses, causing indirect and hard-to-diagnose failures.

**Recommendation:**  
Either let the exception propagate (the test framework will report it clearly), or at minimum re-throw fatal CLR exceptions (check with `ExceptionDispatchInfo` or a helper like `IsFatal()`).

---

### LOW-03 — `mocks.Count > 1` Logic Bug Hides Closest-Match Hint

**File:** `Mockly/HttpMock.cs` (line 274)

```csharp
if (mocks.Count > 1)
{
    foreach (RequestMock mock in mocks) { … }
}
```

**Description:**  
The closest-mock hint is skipped when there is exactly **one** configured mock. This is a correctness bug but also a security-relevant usability issue: when a developer misconfigures the single mock (e.g., wrong method or path), the error message gives no hint about what was configured, making debugging harder and increasing the chance the developer disables `FailOnUnexpectedCalls` instead of fixing the root cause — weakening the security posture of the test suite.

**Recommendation:**  
Change `if (mocks.Count > 1)` to `if (mocks.Count >= 1)`.

---

### LOW-04 — `RequestInfo.Method` Setter Allows Mutation of Captured Request

**File:** `Mockly/RequestInfo.cs` (line 24)

```csharp
public HttpMethod Method
{
    get => request.Method;
    set => request.Method = value;  // mutates the original HttpRequestMessage
}
```

**Description:**  
`RequestInfo` wraps the original `HttpRequestMessage`. The public `Method` setter writes back to the original message object. If a `Matcher` or custom test code mutates `Method` via `RequestInfo`, it silently changes the underlying message that may be shared elsewhere, causing unpredictable behaviour.

**Recommendation:**  
Remove the setter or make `RequestInfo` a proper value-snapshot (copy-on-construction) rather than a live wrapper.

---

### INFORMATIONAL-01 — `#pragma warning disable CA1307/CA1309` for Ordinal Comparisons

**File:** `Mockly/Common/StringExtensions.cs`

Suppressing `CA1307`/`CA1309` on the whole file disables warnings that would catch non-ordinal string comparisons. In `MatchesWildcard`, the equality check `text.Equals(wildcardPattern)` uses the default culture-aware comparison, which can produce surprising results with locale-specific strings (e.g., Turkish `İ`/`i` case folding). This is an edge-case correctness issue that can also be exploited in locale-specific environments.

**Recommendation:**  
Use explicit `StringComparison.OrdinalIgnoreCase` and remove the blanket `#pragma` suppression.

---

### INFORMATIONAL-02 — Analyzers Disabled for `net472` Target

**File:** `Directory.Build.props` (lines 14–18)

```xml
<PropertyGroup Condition="'$(TargetFramework)' != 'net8.0'">
  <RunAnalyzersDuringBuild>false</RunAnalyzersDuringBuild>
  …
</PropertyGroup>
```

Security and code-quality analyzers (StyleCop, Meziantou, Roslynator) are disabled for `net472`. Vulnerabilities that only appear in .NET Framework code paths (e.g., `#if NET472`) will not be caught by the analyzer toolchain.

**Recommendation:**  
While disabling analyzers on older TFMs for build speed is understandable, consider running a dedicated analyzer-only pass on `net472` in CI, or at minimum enable `Meziantou.Analyzer` for all TFMs since it has low overhead.

---

## Risk Summary

| ID | Title | Severity | Effort to Exploit | Exploitable in Production? |
|----|-------|----------|-------------------|---------------------------|
| CRITICAL-01 | ReDoS via `WithBodyMatchingRegex` / `MatchesWildcard` | Critical | Low | No (test-only) |
| CRITICAL-02 | Unbounded static regex cache | Critical | Low | No (test-only) |
| HIGH-01 | Race condition on `List<RequestMock>` | High | Medium | No |
| HIGH-02 | Non-atomic `InvocationCount` / `IsExhausted` | High | Medium | No |
| HIGH-03 | Race condition in `NormalizeHostPatternOnce` | High | Medium | No |
| HIGH-04 | `RequestCollection` not thread-safe | High | Medium | No |
| HIGH-05 | `previousBuilder` shared state race | High | Low | No |
| MEDIUM-01 | Sensitive data in exception messages | Medium | Low | Possible |
| MEDIUM-02 | JSON Bomb via `JsonDocument.Parse` without depth limit | Medium | Low | No |
| MEDIUM-03 | Unbounded body prefetch | Medium | Low | Possible |
| MEDIUM-04 | CI/CD over-broad permissions + secret exposure | Medium | Medium | Yes (CI) |
| MEDIUM-05 | Mutable GitHub Action tags (supply chain) | Medium | High | Yes (CI) |
| LOW-01 | Missing `IDisposable` | Low | Low | No |
| LOW-02 | Exception swallowing in responder | Low | Low | No |
| LOW-03 | `mocks.Count > 1` bug hides hints | Low | Low | No |
| LOW-04 | `RequestInfo.Method` public setter mutates original | Low | Low | No |
| INFO-01 | Culture-sensitive comparisons in `MatchesWildcard` | Info | Low | No |
| INFO-02 | Analyzers disabled for `net472` | Info | — | No |

---

## Recommendations — Priority Order

1. **Immediately:** Add regex timeouts to ALL `Regex.IsMatch` calls (CRITICAL-01).
2. **Immediately:** Bound or make instance-level the static `RegexCache` (CRITICAL-02).
3. **Short-term:** Protect all concurrent data structures with locks or concurrent collections (HIGH-01 through HIGH-05).
4. **Short-term:** Scope CI/CD permissions and secret access to tag-only jobs (MEDIUM-04, MEDIUM-05).
5. **Medium-term:** Redact sensitive request data from error messages (MEDIUM-01).
6. **Medium-term:** Add a configurable body-size limit (MEDIUM-02).
7. **Long-term:** Implement `IDisposable` (LOW-01), fix exception handling (LOW-02), fix the count bug (LOW-03), remove `Method` setter (LOW-04).
