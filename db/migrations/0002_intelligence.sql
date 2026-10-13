-- 0002_intelligence: assets, relationships, observations, evidence, findings, coverage, audit.

CREATE TABLE assets (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id    uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  type          text NOT NULL CHECK (type IN (
                  'DOMAIN','SUBDOMAIN','HOST','IP','CIDR','ASN','URL',
                  'SERVICE','JS_ARTIFACT','API_ENDPOINT','CERTIFICATE','TECHNOLOGY')),
  canonical_key text NOT NULL CHECK (length(canonical_key) > 0),
  value         text NOT NULL CHECK (length(value) > 0),
  first_seen    timestamptz NOT NULL DEFAULT now(),
  last_seen     timestamptz NOT NULL DEFAULT now(),
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, type, canonical_key)
);
CREATE INDEX assets_project_type_idx ON assets (project_id, type);
CREATE INDEX assets_last_seen_idx ON assets (project_id, last_seen DESC);

CREATE TABLE asset_relationships (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id    uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  from_asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  to_asset_id   uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  relation      text NOT NULL CHECK (length(relation) > 0),
  confidence    numeric(4,3) NOT NULL DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
  source        text NOT NULL DEFAULT 'unknown',
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, from_asset_id, to_asset_id, relation),
  CHECK (from_asset_id <> to_asset_id)
);
CREATE INDEX asset_relationships_from_idx ON asset_relationships (from_asset_id);
CREATE INDEX asset_relationships_to_idx ON asset_relationships (to_asset_id);

CREATE TABLE observations (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id         uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_id            uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  asset_id           uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  source             text NOT NULL CHECK (length(source) > 0),
  source_reliability text NOT NULL CHECK (source_reliability IN (
                       'AUTHORITATIVE','HIGH','MEDIUM','LOW','UNKNOWN')),
  observed_at        timestamptz NOT NULL DEFAULT now(),
  first_seen         timestamptz,
  last_seen          timestamptz,
  kind               text NOT NULL CHECK (length(kind) > 0),
  data               jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX observations_project_time_idx ON observations (project_id, observed_at DESC);
CREATE INDEX observations_scan_idx ON observations (scan_id);
CREATE INDEX observations_asset_idx ON observations (asset_id);
CREATE INDEX observations_source_idx ON observations (source);

CREATE TABLE evidence_artifacts (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id   uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_id      uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  sha256       char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  content_type text NOT NULL CHECK (length(content_type) > 0),
  size_bytes   bigint NOT NULL CHECK (size_bytes >= 0),
  storage_uri  text NOT NULL CHECK (length(storage_uri) > 0),
  redacted     boolean NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, sha256)
);
CREATE INDEX evidence_artifacts_scan_idx ON evidence_artifacts (scan_id);

CREATE TABLE findings (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id         uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_id            uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  asset_id           uuid REFERENCES assets(id) ON DELETE SET NULL,
  category           text NOT NULL CHECK (length(category) > 0),
  title              text NOT NULL CHECK (length(title) > 0),
  description        text NOT NULL DEFAULT '',
  severity           text NOT NULL CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  confidence         numeric(4,3) NOT NULL DEFAULT 0.5 CHECK (confidence >= 0 AND confidence <= 1),
  validation         text NOT NULL CHECK (validation IN (
                       'OBSERVED','SUSPECTED','VALIDATED','REJECTED','INDETERMINATE')),
  source_reliability text NOT NULL CHECK (source_reliability IN (
                       'AUTHORITATIVE','HIGH','MEDIUM','LOW','UNKNOWN')),
  first_seen         timestamptz NOT NULL DEFAULT now(),
  last_seen          timestamptz NOT NULL DEFAULT now(),
  created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX findings_project_severity_idx ON findings (project_id, severity);
CREATE INDEX findings_validation_idx ON findings (validation);
CREATE INDEX findings_scan_idx ON findings (scan_id);
CREATE INDEX findings_asset_idx ON findings (asset_id);

CREATE TABLE finding_evidence (
  finding_id  uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  evidence_id uuid NOT NULL REFERENCES evidence_artifacts(id) ON DELETE CASCADE,
  PRIMARY KEY (finding_id, evidence_id)
);

CREATE TABLE evidence_links (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id     uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  artifact_id    uuid NOT NULL REFERENCES evidence_artifacts(id) ON DELETE CASCADE,
  observation_id uuid REFERENCES observations(id) ON DELETE CASCADE,
  finding_id     uuid REFERENCES findings(id) ON DELETE CASCADE,
  note           text NOT NULL DEFAULT '',
  created_at     timestamptz NOT NULL DEFAULT now(),
  CHECK (observation_id IS NOT NULL OR finding_id IS NOT NULL)
);
CREATE INDEX evidence_links_artifact_idx ON evidence_links (artifact_id);

CREATE TABLE coverage_records (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_id    uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  stage      text NOT NULL CHECK (length(stage) > 0),
  status     text NOT NULL CHECK (status IN (
               'COLLECTED','MISSING','PARTIAL','NOT_ATTEMPTED','BLOCKED')),
  expected   integer NOT NULL DEFAULT 0 CHECK (expected >= 0),
  collected  integer NOT NULL DEFAULT 0 CHECK (collected >= 0),
  notes      text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, stage)
);
CREATE INDEX coverage_records_scan_idx ON coverage_records (scan_id);

CREATE TABLE audit_events (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id  uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_id     uuid REFERENCES scan_runs(id) ON DELETE CASCADE,
  at          timestamptz NOT NULL DEFAULT now(),
  actor       text NOT NULL DEFAULT 'system',
  event_type  text NOT NULL CHECK (length(event_type) > 0),
  subject     text NOT NULL DEFAULT '',
  decision    text,
  detail      jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_project_time_idx ON audit_events (project_id, at DESC);
CREATE INDEX audit_events_type_idx ON audit_events (event_type);
