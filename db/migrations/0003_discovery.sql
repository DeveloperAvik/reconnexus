-- 0003_discovery: richer provider execution records and coverage details for Phase 2.

ALTER TABLE provider_executions
  ADD COLUMN duration_ms    integer NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
  ADD COLUMN stderr_bytes   bigint  NOT NULL DEFAULT 0 CHECK (stderr_bytes >= 0),
  ADD COLUMN truncated      boolean NOT NULL DEFAULT false,
  ADD COLUMN timed_out      boolean NOT NULL DEFAULT false,
  ADD COLUMN records_count  integer NOT NULL DEFAULT 0 CHECK (records_count >= 0),
  ADD COLUMN coverage       jsonb   NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE coverage_records
  ADD COLUMN details jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Track provider outcome per job for provider-level coverage reporting.
CREATE TABLE job_provider_outcomes (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id        uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  project_id     uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  job_id         uuid REFERENCES jobs(id) ON DELETE SET NULL,
  stage          text NOT NULL,
  provider       text NOT NULL,
  provider_version text,
  outcome        text NOT NULL CHECK (outcome IN (
                   'SUCCEEDED','PARTIAL','FAILED','SKIPPED','BLOCKED','CANCELLED','SOURCE_UNAVAILABLE')),
  records_count  integer NOT NULL DEFAULT 0 CHECK (records_count >= 0),
  reason         text NOT NULL DEFAULT '',
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, stage, provider)
);
CREATE INDEX job_provider_outcomes_scan_idx ON job_provider_outcomes (scan_id);
