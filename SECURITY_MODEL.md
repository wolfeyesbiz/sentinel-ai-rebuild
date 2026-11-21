# Sentinel AI: abuse-resistance model

**Question from the judges:** couldn't someone use Sentinel to probe other people's websites, or take advantage of a merchant who doesn't know how to fix things?

## What changed

| Before | Now |
|---|---|
| Any signed-in user could add any public URL and scan it | A site is **unverified** until the owner proves control (meta tag, `/.well-known/sentinel-verify.txt`, or DNS TXT). Sentinel sends **zero requests** to an unverified site |
| Anyone could scan any public GitHub repo | GitHub-URL scanning removed. Source review is **upload-only** (you must already hold the code), and only for a verified site |
| Integrations were global | Every integration has an `owner_id`; other users get 404 on list/verify/scan/delete |
| Verification never expired | Re-verify every 30 days |
| No limits/audit | Max 5 sites per user, per-site cooldowns, audit log line for every check |

## Why this is safe against the "freelancer" scenario
* Sentinel's integration key is **write-only**: it can push request telemetry in, it cannot read anything from the store or the site.
* Sentinel never logs in, never reads customer/order data, and reports contain header/config-level findings and ready-to-paste fixes, not exploit payloads or data.
* The merchant can apply the fixes themselves from the copy-paste snippets, so nobody has to be handed access.
* A stranger who gets a copy of the report still cannot run Sentinel against the site (not the owner's account, not verified for them).

## Known limits (be honest with judges)
* Public-facing header checks reveal nothing that tools like SecurityHeaders / SSL Labs don't already show for any URL; the value of verification is that active checks and source review are owner-only.
* Telemetry/alerts/dashboards are still one shared store. Per-user isolation of alerts and traffic is the next step.
* Integrations are in memory; move them to the DB so verification survives restarts.
