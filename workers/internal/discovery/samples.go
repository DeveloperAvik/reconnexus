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
	}
}
