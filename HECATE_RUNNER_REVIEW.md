# Hecate-Runner Comprehensive Review

After analyzing the `Hecate-Runner` project, several bugs and suboptimal components were identified across the intake triage, orchestrator logic, and grounding auditing features. 

## 1. CTI Triage Fails to Process MISP and OTX Tags (Bug)
In `cti_triage.py`, the `_categories` function retrieves tags directly via `item.metadata.get("entry_tags")`. 
```python
def _categories(item: CTIItem) -> list[str]:
    raw: Any = item.metadata.get("entry_tags") or []
    return [str(t).strip().lower() for t in raw if str(t).strip()]
```
While this correctly parses RSS feeds (since `src/hecate_runner/cti/rss.py` populates the `entry_tags` metadata field), both `otx.py` and `misp.py` **do not set the `entry_tags` key** in their emitted metadata dictionaries. Consequently, `_categories` returns an empty list for all OTX and MISP events.

**Impact:** All tag-based triage rules are completely bypassed for OTX pulses and MISP events. The triage engine is severely degraded for these providers, as it will only fall back to evaluating title regexes (`_COMMENTARY_TITLE_PATTERNS`) to identify non-actionable commentary.

## 2. Inaccurate `_PLATFORM_MENTIONS` Substring Matching (Suboptimal/Bug)
In `orchestrator.py`, the `platforms_named_in` function performs a naive substring search when attempting to determine if a platform was claimed in the hypothesis text:
```python
def platforms_named_in(*texts: str) -> list[str]:
    haystack = " ".join(t for t in texts if t).lower()
    named: list[str] = []
    for mention, platform in _PLATFORM_MENTIONS.items():
        if mention in haystack and platform not in named:
            named.append(platform)
    return named
```
Since it simply checks `if mention in haystack` without word boundaries (`\b`), false positives can easily occur. For instance:
* The word `saas` will match if the text contains a word like `isaas`.
* The word `azure` will match substrings like `azureus`.
* `mac os` could be falsely triggered.

**Impact:** Platform arrays in draft frontmatters might contain inappropriately derived platform limitations, potentially causing inaccurate scoping.

## 3. Grounding Audit - Missing Filename Extensions (Suboptimal)
In `grounding.py`, the `_looks_like_a_filename` function determines whether a domain-shaped string is actually a filename by checking its suffix against `_FILE_SUFFIXES`.
```python
def _looks_like_a_filename(value: str) -> bool:
    if "/" in value or "\\" in value:
        return True
    return value.rsplit(".", 1)[-1].lower() in _FILE_SUFFIXES
```
The `_FILE_SUFFIXES` list deliberately excludes valid Top-Level Domains (TLDs) like `.com` or `.sh` to prevent fabricated C2 domains from passing the audit. However, this implementation means any filename ending with an unknown/unlisted extension (e.g., `config.local`, `update.bin`, `service.pid`) that doesn't include a path separator `/` or `\` will fail the `_looks_like_a_filename` check.

**Impact:** Valid behavioral rules or statements looking for generic filename patterns like `update.bin` will be falsely audited and reported as **Unsupported fabricated domains**.

## 4. Suboptimal State Drift in `grounding.py` Comments
The `grounding.py` `TechniqueFact` documentation claims:
> `The orchestrator already resolves every technique through hecate-agent attack lookup to derive tactics and platforms, and each of those is a subprocess call. Re-running them inside the audit would double the cost...`

This represents configuration drift from `ARCHITECTURE.md` and the actual implementation in `hecate_client.py`, which shows that `hecate_agent.api` methods are now called **in-process**, heavily relying on process-level `os.chdir` context manager wrappers, rather than through literal subprocess shells. The assumption of extreme subprocess penalty here led to potentially complicated caching (`technique_facts`) being passed around unnecessarily when the internal `lookup_technique` natively uses an already-memoized STIX index.

## 5. Incomplete MISP Mapping in `indicator_sweep.py`
`hecate_runner/indicator_sweep.py` maps explicit indicator types via `_TELEMETRY_BY_TYPE`. While the MISP `ip-dst|port` format is covered, `ip-src|port` is entirely missing from the map. 

**Impact:** If a MISP event specifies `ip-src|port` indicators, they will fall back to an unmapped state (triggering the `Presence of a listed ip-src|port indicator` generic rule) and fail to contribute the `"Network flow / firewall logs"` source to the generated hunt's `data_sources`.

## 6. Heavy Env Context Switching in `hecate_client.py`
`hecate_client.py` runs an in-process wrapper `_with_context` for almost every Hecate Core API hit.
```python
def _with_context(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    original_cwd = os.getcwd()
    original_env = os.environ.copy()
    try:
        os.chdir(self.workspace)
        from dotenv import load_dotenv
        load_dotenv(self.workspace / ".env")
        os.environ.update(self.env_overrides)
        return func(*args, **kwargs)
    ...
```
**Impact:** Because functions like `lookup_technique` are invoked iteratively inside tight `for` loops (e.g. `_resolve_ttps`), the application rapidly performs disk I/O to read `.env` and toggles the CWD back and forth. This introduces unnecessary I/O overhead that scales linearly with the number of ATT&CK techniques or queries. `_with_context` state caching should be optimized to load variables once.
