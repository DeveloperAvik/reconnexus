-- 0011_github_wayback: add GITHUB_LEAK_SEARCH and WAYBACK_DIFF capabilities.
--
-- Same shape as 0010_graphql_param_discovery: only the CHECK constraint is replaced, no data is
-- altered. Rollback: re-add the previous constraint without these two capabilities (existing
-- rows that use either would need to be updated first).

ALTER TABLE authorization_records
  DROP CONSTRAINT IF EXISTS authorization_records_capabilities_check;

ALTER TABLE authorization_records
  ADD CONSTRAINT authorization_records_capabilities_check CHECK (
    capabilities <@ ARRAY[
      'PASSIVE','DNS','ACTIVE_HTTP','CRAWL','JS_ANALYSIS',
      'API_DISCOVERY','SECRET_SCAN','SECURITY_CHECKS',
      'ACTIVE_TEMPLATE_CHECK','TAKEOVER_CHECK','PORT_SCAN','CONTENT_DISCOVERY',
      'CLOUD_STORAGE_CHECK','CORS_REDIRECT_CHECK','GRAPHQL_INTROSPECTION',
      'PARAMETER_DISCOVERY','GITHUB_LEAK_SEARCH','WAYBACK_DIFF','INTERNAL_NETWORK'
    ]::text[]
  );
