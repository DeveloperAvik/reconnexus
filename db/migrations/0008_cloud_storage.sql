-- 0008_cloud_storage: add the CLOUD_STORAGE_CHECK capability to the authorization capability constraint.
--
-- Same shape as 0007_content_discovery: only the CHECK constraint is replaced, no data is altered.
-- Rollback: re-add the previous constraint without 'CLOUD_STORAGE_CHECK' (existing rows that use it
-- would need to be updated first).

ALTER TABLE authorization_records
  DROP CONSTRAINT IF EXISTS authorization_records_capabilities_check;

ALTER TABLE authorization_records
  ADD CONSTRAINT authorization_records_capabilities_check CHECK (
    capabilities <@ ARRAY[
      'PASSIVE','DNS','ACTIVE_HTTP','CRAWL','JS_ANALYSIS',
      'API_DISCOVERY','SECRET_SCAN','SECURITY_CHECKS',
      'ACTIVE_TEMPLATE_CHECK','TAKEOVER_CHECK','PORT_SCAN','CONTENT_DISCOVERY',
      'CLOUD_STORAGE_CHECK','INTERNAL_NETWORK'
    ]::text[]
  );
