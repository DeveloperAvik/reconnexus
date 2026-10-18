-- 0005_observation_identity: database-level idempotency backstop for observations.
--
-- Identity of an observation: (project_id, scan_id, asset_id, source, kind, md5(data::text)).
--   * scan_id is part of the identity: the same fact seen in a later scan is new history
--     (diff/changes/report rely on per-scan observations), only replays within one scan collapse.
--   * asset_id + source + kind scope the fact; ingest already chooses the asset per record type.
--   * data is hashed over its canonical jsonb text (keys sorted, whitespace normalised), so every
--     meaningful payload difference (status, value, TTL, resolver, url, ...) stays distinct while
--     key order never matters. md5 keeps index entries small regardless of payload size.
--   * observed_at/created_at are deliberately excluded: a replay carries a new timestamp.
--
-- Existing duplicates (identical identity) are reconciled, not blindly deleted:
--   1. keeper = earliest row by (observed_at, created_at, id);
--   2. keeper.first_seen/last_seen widen to cover every row in the group;
--   3. evidence_links of duplicates are repointed to the keeper (exact duplicate links dropped);
--   4. every removed row is copied in full to observations_dedup_archive before deletion.

-- Block concurrent writers while duplicates are reconciled (reads continue).
LOCK TABLE observations, evidence_links IN SHARE ROW EXCLUSIVE MODE;

-- The ON DELETE CASCADE from observations had no supporting index; without it every deleted
-- observation seq-scans evidence_links.
CREATE INDEX IF NOT EXISTS evidence_links_observation_idx ON evidence_links (observation_id);

CREATE TABLE IF NOT EXISTS observations_dedup_archive (
  archived_at timestamptz NOT NULL DEFAULT now(),
  kept_id     uuid NOT NULL,
  reason      text NOT NULL DEFAULT 'duplicate-identity (0005)',
  row_data    jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS observations_dedup_archive_kept_idx ON observations_dedup_archive (kept_id);

CREATE TEMP TABLE _obs_dups ON COMMIT DROP AS
SELECT id,
       first_value(id) OVER w AS keeper_id,
       row_number()   OVER w AS rn
FROM observations
WINDOW w AS (PARTITION BY project_id, scan_id, asset_id, source, kind, md5(data::text)
             ORDER BY observed_at, created_at, id);
DELETE FROM _obs_dups d USING (
  SELECT keeper_id FROM _obs_dups GROUP BY keeper_id HAVING count(*) = 1
) s WHERE d.keeper_id = s.keeper_id;

-- 2. widen keeper's seen window
UPDATE observations k
SET first_seen = LEAST(COALESCE(k.first_seen, k.observed_at), m.min_seen),
    last_seen  = GREATEST(COALESCE(k.last_seen, k.observed_at), m.max_seen)
FROM (
  SELECT d.keeper_id,
         min(LEAST(o.observed_at, COALESCE(o.first_seen, o.observed_at))) AS min_seen,
         max(GREATEST(o.observed_at, COALESCE(o.last_seen, o.observed_at))) AS max_seen
  FROM _obs_dups d JOIN observations o ON o.id = d.id
  GROUP BY d.keeper_id
) m
WHERE k.id = m.keeper_id;

-- 3. repoint evidence links, then drop links that became exact duplicates
UPDATE evidence_links el SET observation_id = d.keeper_id
FROM _obs_dups d WHERE el.observation_id = d.id AND d.rn > 1;
DELETE FROM evidence_links el USING (
  SELECT id, row_number() OVER (PARTITION BY project_id, artifact_id, observation_id, finding_id, note
                                ORDER BY created_at, id) AS rn
  FROM evidence_links
  WHERE observation_id IN (SELECT keeper_id FROM _obs_dups)
) x WHERE el.id = x.id AND x.rn > 1;

-- 4. archive, then delete the duplicates
INSERT INTO observations_dedup_archive (kept_id, row_data)
SELECT d.keeper_id, to_jsonb(o) FROM _obs_dups d JOIN observations o ON o.id = d.id WHERE d.rn > 1;
DELETE FROM observations o USING _obs_dups d WHERE o.id = d.id AND d.rn > 1;

CREATE UNIQUE INDEX observations_identity_uidx
  ON observations (project_id, scan_id, asset_id, source, kind, (md5(data::text)));
