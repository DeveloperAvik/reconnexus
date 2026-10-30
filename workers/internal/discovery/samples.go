package discovery

// RecordTypes is every record type a provider may emit, in contract order.
var RecordTypes = []string{
	TypeHostObservation,
	TypeDNSRecord,
	TypeIPMetadata,
	TypeHTTPObservation,
	TypeTechnology,
	TypeURLObservation,
	TypeJSArtifact,
	TypeSourceMap,
	TypeApiSpec,
	TypeApiEndpoint,
	TypeSecurityMetadata,
	TypeSecretCandidate,
	TypeSecretScanArtifact,
	TypeTakeoverCandidate,
	TypeLoginInterface,
	TypePortObservation,
	TypeTemplateFinding,
	TypeContentDiscovery,
	TypeCloudStorage,
	TypeCorsMisconfig,
	TypeOpenRedirect,
	TypeEmailSecurity,
	TypeGraphQLSchema,
	TypeParamDiscovery,
	TypeGithubCodeMatch,
	TypeWaybackDiff,
}

// SampleRecords returns one representative record per record type. It is the input to the
// cross-language record-shape check: the samples are marshalled by the Go worker and validated
// against DiscoveryRecordSchema in packages/contracts, so a field that drifts between the two
// languages fails a test instead of silently failing a live scan.
//
// Nested collections are deliberately left nil here; Run normalizes records before emitting
// them, and the check asserts that normalization leaves no `null` where the contract declares
// an array or an object.
func SampleRecords() []Record {
	status := 200
	ttl := 300
	consistent := true
	return []Record{
		{Type: TypeHostObservation, Host: "app.example.com", Source: "dns", Provider: "builtin-dns", Status: HostResolved, Notes: ""},
		{Type: TypeDNSRecord, Name: "app.example.com", RecordType: "A", Value: "203.0.113.10", TTL: &ttl, Status: "NOERROR", Resolver: "system"},
		{Type: TypeIPMetadata, IP: "203.0.113.10", Source: "rdap", Confidence: 0.6, Prefix: strPtr("203.0.113.0/24"), ASNOrg: strPtr("Example Org"), NetworkName: strPtr("EXAMPLE-NET"), Country: strPtr("US")},
		{Type: TypeHTTPObservation, URL: "https://app.example.com/", Host: "app.example.com", Provider: "builtin-http", Source: "http", HTTP: &HTTPDetails{
			FinalURL:    "https://app.example.com/",
			StatusCode:  &status,
			StatusText:  "200 OK",
			ContentType: "text/html",
			Title:       "Example",
			ProbeStatus: ProbeOK,
			TLS:         &TLSInfo{Subject: "CN=app.example.com", Issuer: "CN=Example CA", Protocol: "TLS1.3"},
		}},
		{Type: TypeTechnology, URL: "https://app.example.com/", Host: "app.example.com", Provider: "builtin-http", Technology: &TechDetails{
			Name: "nginx", Category: "WEB_SERVER", EvidenceType: "HEADER", Evidence: "server: nginx", Confidence: 0.8,
		}},
		{Type: TypeURLObservation, URL: "https://app.example.com/search?q=1", CanonicalURL: "https://app.example.com/search?q=1", Host: "app.example.com", Provider: "builtin-crawler", Source: "crawl", Method: MethodCrawl, Depth: 1, StatusCode: &status,
			Classifications: []UrlClassification{{Category: "SEARCH", Confidence: 0.7, EvidenceType: "PATH", Evidence: "/search"}},
			Parameters:      []UrlParameter{{Name: "q"}},
		},
		{Type: TypeJSArtifact, URL: "https://app.example.com/main.js", CanonicalURL: "https://app.example.com/main.js", Provider: "builtin-js", Source: "js", Artifact: &JsArtifactInfo{
			URL: "https://app.example.com/main.js", CanonicalURL: "https://app.example.com/main.js",
			ContentHash: "0000000000000000000000000000000000000000000000000000000000000000",
			ContentType: "application/javascript", SizeBytes: 1024, SourceURL: "https://app.example.com/",
			DiscoveryMethod: "stage05", Status: ArtifactRetrieved,
		}},
		{Type: TypeSourceMap, URL: "https://app.example.com/main.js.map", Provider: "builtin-js", Source: "sourcemap", SourceMap: &SourceMapInfo{
			JsURL: "https://app.example.com/main.js", SourceMapURL: "https://app.example.com/main.js.map",
			Status: "PARSED", SourcesCount: 1, HasContent: true,
		}},
		{Type: TypeApiSpec, URL: "https://app.example.com/openapi.json", Provider: "builtin-api", Source: "spec", ApiSpec: &ApiSpecInfo{
			URL: "https://app.example.com/openapi.json", SpecVersion: "openapi:3.0.0", Title: "Example API",
			Format: "JSON", PathCount: 1, OperationCount: 1, ParseStatus: "PARSED",
		}},
		{Type: TypeApiEndpoint, URL: "https://app.example.com/api/users", Provider: "builtin-api", Source: "spec", Endpoint: &ApiEndpoint{
			Method: "GET", Origin: "https://app.example.com", Path: "/api/users", URL: "https://app.example.com/api/users",
			DiscoveredVia: ViaSpec, Documented: true, Resolved: true, OperationID: "listUsers",
			SourceURL: "https://app.example.com/openapi.json", Evidence: "declared", EvidenceType: "OPENAPI",
		}},
		{Type: TypeSecurityMetadata, URL: "https://app.example.com/", Host: "app.example.com", Provider: "builtin-security-meta", Source: "response", Security: &SecurityMetadataInfo{
			Category: CatHeader, Name: "strict-transport-security", Status: MetaObserved, Observed: true,
			Value: "max-age=31536000", Consistent: &consistent, Evidence: "response header", EvidenceType: "HEADER",
		}},
		{Type: TypeSecretCandidate, Provider: "builtin-secret-scan", Source: "js", Secret: &SecretCandidateInfo{
			RuleID: "generic-api-key", Category: "API_KEY", Status: SecretCandidate, Confidence: 0.5,
			ArtifactURL: "https://app.example.com/main.js", Host: "app.example.com", Location: "12:5",
			RedactedSnippet: "apiKey: \"[REDACTED]\"", Fingerprint: "", Occurrences: 1, Rationale: "matched rule",
		}},
		{Type: TypeSecretScanArtifact, Provider: "builtin-secret-scan", Source: "js", SecretScan: &SecretScanArtifactInfo{
			ArtifactURL: "https://app.example.com/main.js", Host: "app.example.com",
			Status: SecretArtifactAnalyzed, FindingsCount: 1, RawBytes: 1024, HMACKeyed: false,
		}},
		{Type: TypeTakeoverCandidate, URL: "https://app.example.com/", Host: "app.example.com", Provider: "builtin-takeover", Source: "takeover", Takeover: &TakeoverInfo{
			Host: "app.example.com", CNAME: "app.example.com.github.io", Service: "GitHub Pages",
			Status: TakeoverSuspected, Confidence: 0.8, HTTPStatus: &status,
			Evidence:     "CNAME app.example.com -> app.example.com.github.io (GitHub Pages); unclaimed marker matched",
			EvidenceType: "UNCLAIMED_MARKER",
		}},
		{Type: TypeLoginInterface, URL: "https://app.example.com/admin/login", Host: "app.example.com", Provider: "builtin-login-finder", Source: "login-finder", Login: &LoginInterfaceInfo{
			Kind: LoginKindAdmin, Status: LoginDetected, Confidence: 0.85,
			FinalURL: "https://app.example.com/admin/login", HTTPStatus: &status, Title: "Admin Login",
			Evidence: "HTTP 200; password form present; title \"Admin Login\"", EvidenceType: "LOGIN_FORM",
		}},
		{Type: TypePortObservation, Host: "app.example.com", IP: "93.184.216.34", Provider: "nmap", Source: "nmap", Port: &PortInfo{
			Port: 443, Protocol: "tcp", State: "OPEN", Service: "http", Product: "nginx", Version: "1.24.0", TLS: true, Confidence: 0.8,
		}},
		{Type: TypeTemplateFinding, Host: "app.example.com", URL: "https://app.example.com/.git/config", Provider: "nuclei", Source: "nuclei", Template: &TemplateInfo{
			TemplateID: "git-config", Name: "Git Config Exposure", Severity: "MEDIUM", Description: "A git configuration file is publicly readable.",
			Tags: []string{"exposure", "git"}, References: []string{"https://example.com/ref"}, MatcherName: "", Extracted: []string{}, TemplateType: "http", Confidence: 0.7,
		}},
		{Type: TypeContentDiscovery, Host: "app.example.com", URL: "https://app.example.com/.git/HEAD", Provider: "builtin-content", Source: "content-discovery", Content: &ContentInfo{
			Path: "/.git/HEAD", Category: ContentVCS, Status: ContentConfirmed, Severity: "HIGH", Confidence: 0.9, HTTPStatus: 200,
			ContentSize: 23, ContentType: "text/plain", Title: "", Evidence: "content marker present: git HEAD reference", EvidenceType: "CONTENT_MARKER",
		}},
		{Type: TypeCloudStorage, Host: "static.example.com", URL: "https://static.example.com/", Provider: "builtin-cloud-storage", Source: "cloud-storage", CloudStorage: &CloudStorageInfo{
			CloudProvider: CloudProviderS3, Bucket: "static.example.com", Origin: "CUSTOM_DOMAIN", Status: CloudStorageListable, Confidence: 0.9,
			HTTPStatus: &status, ObjectCount: 42, Evidence: "HTTP 200 with a <ListBucketResult> object listing", EvidenceType: "LIST_BUCKET_RESULT",
		}},
		{Type: TypeCorsMisconfig, Host: "app.example.com", URL: "https://app.example.com/api/account", Provider: "builtin-cors-redirect", Source: "cors-redirect", Cors: &CorsInfo{
			Status: CorsReflectsArbitraryOriginWithCredentials, Confidence: 0.9, AllowOrigin: "https://cors-probe.reconnexus.invalid", AllowCredentials: true,
			TestedOrigin: "https://cors-probe.reconnexus.invalid", HTTPStatus: &status,
			Evidence: "Access-Control-Allow-Origin reflected the arbitrary Origin sent, with Access-Control-Allow-Credentials: true", EvidenceType: "REFLECTED_ORIGIN_WITH_CREDENTIALS",
		}},
		{Type: TypeOpenRedirect, Host: "app.example.com", URL: "https://app.example.com/login?next=/dashboard", Provider: "builtin-cors-redirect", Source: "cors-redirect", OpenRedirect: &OpenRedirectInfo{
			TestedURL: "https://app.example.com/login?next=https%3A%2F%2Fredirect-canary.reconnexus.invalid%2F", Parameter: "next", Status: RedirectConfirmed, Confidence: 0.9,
			HTTPStatus: &status, Location: "https://redirect-canary.reconnexus.invalid/",
			Evidence: "redirected to the injected externally-controlled value", EvidenceType: "REDIRECTED_TO_CANARY",
		}},
		{Type: TypeEmailSecurity, Host: "example.com", Provider: "builtin-email-security", Source: "email-security", EmailSecurity: &EmailSecurityInfo{
			Category: EmailCategoryDMARC, Status: EmailSecurityWeak, Confidence: 0.8, Value: "v=DMARC1; p=none; pct=100; rua=mailto:dmarc@example.com",
			Detail:   map[string]any{"hasMx": true, "policy": "none", "pct": "100"},
			Evidence: "DMARC policy is p=none (monitoring only; failing mail is not rejected or quarantined)", EvidenceType: "MONITOR_ONLY",
		}},
		{Type: TypeGraphQLSchema, Host: "app.example.com", URL: "https://app.example.com/graphql", Provider: "builtin-graphql", Source: "graphql", GraphQL: &GraphQLInfo{
			Status: GraphQLIntrospectionEnabled, Confidence: 0.95, HTTPStatus: &status, QueryType: "Query", MutationType: "Mutation", SubscriptionType: "",
			TypeCount: 42, QueryFieldCount: 12, MutationFieldCount: 5,
			Evidence: "introspection query returned a non-null __schema object", EvidenceType: "SCHEMA_DISCLOSED",
		}},
		{Type: TypeParamDiscovery, Host: "app.example.com", URL: "https://app.example.com/search", Provider: "builtin-param-discovery", Source: "param-discovery", ParamDiscovery: &ParamDiscoveryInfo{
			Parameter: "debug", Confidence: 0.85, HTTPStatus: &status, BaselineStatus: &status, BaselineLength: 1024, TestLength: 1180,
			Evidence: "injected probe value for parameter \"debug\" was reflected in the response", EvidenceType: "REFLECTED_VALUE",
		}},
		{Type: TypeGithubCodeMatch, Host: "example.com", URL: "https://github.com/someorg/somerepo/blob/main/config.yml", Provider: "builtin-github-leaks", Source: "github", GithubMatch: &GithubCodeMatchInfo{
			Query: "example.com", Repository: "someorg/somerepo", Path: "config.yml", SHA: "abc123", Score: 1.0,
			Evidence: "endpoint: https://api.example.com/v1 # [REDACTED]", EvidenceType: "CODE_MATCH",
		}},
		{Type: TypeWaybackDiff, Host: "example.com", URL: "https://example.com/old-admin/", Provider: "builtin-wayback-diff", Source: "wayback", WaybackDiff: &WaybackDiffInfo{
			FirstSeen: "20180512000000", LastStatus: 200, MimeType: "text/html", Confidence: 0.5,
			Evidence: "archived by the Wayback Machine returning HTTP 200, but not observed by this scan's own crawl", EvidenceType: "NOT_CURRENTLY_OBSERVED",
		}},
	}
}
