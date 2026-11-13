# Security event backlog (initial)

Migration 0005 creates `security_events` and changes security invalidation triggers to insert an event in the same transaction as the state change, alongside existing PostgreSQL NOTIFY. API-originated events also go to the event log. Connected instances poll the log every five seconds, and retain their existing immediate notification path plus periodic session and membership revalidation.

**Not a proven durable/fenced system:** sequence IDs are assigned before commit, so concurrent transactions can commit out of order and cause a high-water-mark cursor to skip an older ID. The current catch-up is bounded to 2,000 events per tick and initializes at the latest ID on process start (there are no existing WebSocket clients after restart). Notifications can duplicate delivery. No replay acknowledgment, partition recovery/fencing protocol, metrics, explicit RPO or validated latency SLO exists. These remain P0 release blockers. Backlog needs scheduled retention after defining replica outage tolerances and compliance requirements.

Do not expose payloads to end users. Protect database privileges and test concurrent commit ordering before relying on event log replay as an authorization guarantee.
