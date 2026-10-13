-- 0001_core: workspaces, projects, authorization, scope, scans, jobs, provider executions.

CREATE TABLE workspaces (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL CHECK (length(name) > 0),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email       text NOT NULL UNIQUE CHECK (position('@' in email) > 1),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role         text NOT NULL CHECK (role IN ('OWNER', 'ADMIN', 'MEMBER', 'VIEWER')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE projects (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name        text NOT NULL CHECK (length(name) > 0),
  root_domain text NOT NULL CHECK (length(root_domain) > 0),
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, name)
);

CREATE TABLE authorization_records (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id     uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  reference      text NOT NULL CHECK (length(reference) > 0),
  authorized_by  text NOT NULL CHECK (length(authorized_by) > 0),
  valid_from     timestamptz NOT NULL,
  valid_until    timestamptz NOT NULL,
  capabilities   text[] NOT NULL CHECK (
                   capabilities <@ ARRAY[
                     'PASSIVE','DNS','ACTIVE_HTTP','CRAWL','JS_ANALYSIS',
                     'API_DISCOVERY','SECRET_SCAN','SECURITY_CHECKS',
                     'ACTIVE_TEMPLATE_CHECK','INTERNAL_NETWORK'
                   ]::text[]
                 ),
  created_at     timestamptz NOT NULL DEFAULT now(),
  CHECK (valid_until > valid_from)
);

-- Immutable, versioned scope policy documents. UNIQUE (project_id, version).
CREATE TABLE scope_policies (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id  uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  version     integer NOT NULL CHECK (version > 0),
  document    jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (project_id, version)
);

CREATE TABLE scan_runs (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id      uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  policy_id       uuid NOT NULL REFERENCES scope_policies(id),
  status          text NOT NULL DEFAULT 'QUEUED' CHECK (status IN (
                    'QUEUED','RUNNING','SUCCEEDED','PARTIAL','FAILED',
                    'SKIPPED','BLOCKED','CANCELLED','SOURCE_UNAVAILABLE')),
  start_url       text NOT NULL,
  root_domain     text NOT NULL,
  config_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  coverage        jsonb NOT NULL DEFAULT '{}'::jsonb,
  error           text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  started_at      timestamptz,
  finished_at     timestamptz
);
CREATE INDEX scan_runs_project_idx ON scan_runs (project_id, created_at DESC);
CREATE INDEX scan_runs_status_idx ON scan_runs (status);

CREATE TABLE jobs (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id         uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  project_id      uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  stage           text NOT NULL CHECK (length(stage) > 0),
  job_key         text NOT NULL CHECK (length(job_key) > 0),
  depends_on      text[] NOT NULL DEFAULT '{}',
  status          text NOT NULL DEFAULT 'QUEUED' CHECK (status IN (
                    'QUEUED','RUNNING','SUCCEEDED','PARTIAL','FAILED',
                    'SKIPPED','BLOCKED','CANCELLED','SOURCE_UNAVAILABLE')),
  attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts    integer NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
  not_before      timestamptz NOT NULL DEFAULT now(),
  deadline        timestamptz,
  lease_expires_at timestamptz,
  worker_id       text,
  last_error      text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (scan_id, job_key)
);
CREATE INDEX jobs_claimable_idx ON jobs (status, not_before) WHERE status = 'QUEUED';
CREATE INDEX jobs_scan_idx ON jobs (scan_id);
CREATE INDEX jobs_lease_idx ON jobs (lease_expires_at) WHERE status = 'RUNNING';

CREATE TABLE provider_executions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id          uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  job_id           uuid REFERENCES jobs(id) ON DELETE SET NULL,
  provider         text NOT NULL,
  provider_version text,
  argv             text[] NOT NULL DEFAULT '{}',
  exit_code        integer,
  status           text NOT NULL CHECK (status IN (
                     'QUEUED','RUNNING','SUCCEEDED','PARTIAL','FAILED',
                     'SKIPPED','BLOCKED','CANCELLED','SOURCE_UNAVAILABLE')),
  stdout_bytes     bigint NOT NULL DEFAULT 0 CHECK (stdout_bytes >= 0),
  stderr_excerpt   text,
  error            text,
  started_at       timestamptz NOT NULL DEFAULT now(),
  finished_at      timestamptz
);
CREATE INDEX provider_executions_scan_idx ON provider_executions (scan_id);
CREATE INDEX provider_executions_provider_idx ON provider_executions (provider);
