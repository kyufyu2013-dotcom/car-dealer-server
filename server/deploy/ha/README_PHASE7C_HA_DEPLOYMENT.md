# Phase 7C — Primary / Standby deployment

This release adds application awareness for a real PostgreSQL Primary/Standby pair. It does **not** pretend that Node.js can create physical replication by itself. PostgreSQL streaming replication, WAL archiving, network fencing/VIP/DNS, and promotion must be configured at the infrastructure layer.

## Recommended topology

- Central App A -> PostgreSQL Primary
- Central App B -> PostgreSQL Standby (streaming replica)
- Load balancer probes `/api/ready`
- Only the instance whose database is Primary returns HTTP 200 from `/api/ready`
- Standby returns 503 for readiness and rejects all mutating `/api` requests
- After the database Standby is promoted, App B detects `pg_is_in_recovery() = false`, runs any pending schema migration under the existing advisory migration lock, and becomes write-ready automatically.

## Environment variables

```env
CENTRAL_HA_ENABLED=true
CENTRAL_HA_INSTANCE_ID=central-a
CENTRAL_HA_SITE=site-a
CENTRAL_HA_EXPECTED_ROLE=primary
CENTRAL_HA_PEER_URL=https://standby.example.com
CENTRAL_HA_PEER_TIMEOUT_MS=3500
```

On the second app instance use a different instance/site and point `DATABASE_URL` to the PostgreSQL physical standby.

## Safe deployment order

1. Back up the current Primary and verify the backup.
2. Deploy/migrate the Primary first until Schema v8 is complete.
3. Confirm WAL replication has applied Schema v8 to the Standby.
4. Deploy the Standby app. It must report `dbRole=standby` and `/api/ready` must return 503.
5. Configure the load balancer to use `/api/ready`, not `/api/health`.
6. Perform a controlled failover drill: fence the old Primary from writes, promote the Standby, then confirm `/api/ready` becomes 200 on the promoted side.
7. Rebuild the old Primary as a new Standby before returning to normal redundancy.

## Important

Never run two writable PostgreSQL primaries at the same time. Avoid split-brain by using a proper failover manager/cloud database service or strict operational fencing. `/api/health` is liveness; `/api/ready` is write-readiness.
