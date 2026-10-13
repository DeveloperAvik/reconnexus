-- 0004_takeover: add the TAKEOVER_CHECK capability to the authorization capability constraint.
--
-- The original constraint (0001_core) enumerated the known capabilities. Adding a new capability
-- requires extending that allow-list. No data is altered; only the CHECK constraint is replaced.
-- Rollback: re-add the previous constraint without 'TAKEOVER_CHECK' (existing rows that use it
-- would need to be updated first).

ALTER TABLE authorization_records
  DROP CONSTRAINT IF EXISTS authorization_records_capabilities_check;

ALTER TABLE authorization_records
  ADD CONSTRAINT authorization_records_capabilities_check CHECK (
    capabilities <@ ARRAY[
      'PASSIVE','DNS','ACTIVE_HTTP','CRAWL','JS_ANALYSIS',
      'API_DISCOVERY','SECRET_SCAN','SECURITY_CHECKS',
      'ACTIVE_TEMPLATE_CHECK','TAKEOVER_CHECK','INTERNAL_NETWORK'
    ]::text[]
  );
