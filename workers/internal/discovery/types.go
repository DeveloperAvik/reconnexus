// Package discovery implements the provider execution lifecycle for subdomain discovery,
// DNS intelligence, and infrastructure correlation. It mirrors the JSON contracts in
// packages/contracts/src/discovery.ts and enforces scope independently of the control plane.
package discovery

import "github.com/reconnexus/workers/internal/scope"

// Job is the worker input (mirrors DiscoveryJobSchema).
type Job struct {
	SchemaVersion            int          `json:"schemaVersion"`
	ScanID                   string       `json:"scanId"`
	ProjectID                string       `json:"projectId"`
	Stage                    string       `json:"stage"`
	JobKey                   string       `json:"jobKey"`
	Kind                     string       `json:"kind"`
	Provider                 string       `json:"provider"`
	Policy                   scope.Policy `json:"policy"`
	Limits                   scope.Limits `json:"limits"`
	Inputs                   Inputs       `json:"inputs"`
	AllowRestrictedAddresses bool         `json:"allowRestrictedAddresses"`
	BinaryPath               string       `json:"binaryPath,omitempty"`
	FixturePath              string       `json:"fixturePath,omitempty"`
	ResolverAddress          string       `json:"resolverAddress,omitempty"`
	RdapBaseURL              string       `json:"rdapBaseUrl,omitempty"`
	WorkDir                  string       `json:"workDir,omitempty"`
	TimeoutMs                int          `json:"timeoutMs,omitempty"`
	MaxOutputBytes           int          `json:"maxOutputBytes,omitempty"`
	MaxRedirects             int          `json:"maxRedirects,omitempty"`
	RequestTimeoutMs         int          `json:"requestTimeoutMs,omitempty"`
	TLSCaFile                string       `json:"tlsCaFile,omitempty"`
}

type Inputs struct {
	RootDomain      string         `json:"rootDomain,omitempty"`
	Names           []string       `json:"names,omitempty"`
	Addresses       []AddressInput `json:"addresses,omitempty"`
	URLs            []string       `json:"urls,omitempty"`
	SeedURLs        []string       `json:"seedUrls,omitempty"`
	Domains         []string       `json:"domains,omitempty"`
	CrawlDepth      int            `json:"crawlDepth,omitempty"`
	RequestBudget   int            `json:"requestBudget,omitempty"`
	JSURLs          []string       `json:"jsUrls,omitempty"`
	SpecURLs        []string       `json:"specUrls,omitempty"`
	SpecProbeURLs   []string       `json:"specProbeUrls,omitempty"`
	FetchSourceMaps bool           `json:"fetchSourceMaps,omitempty"`
	ArtifactURLs    []string       `json:"artifactUrls,omitempty"`
	Ports           string         `json:"ports,omitempty"`
	TemplateTags    string         `json:"templateTags,omitempty"`
}

type AddressInput struct {
	IP      string `json:"ip"`
	ViaHost string `json:"viaHost"`
}

// Result is the worker output (mirrors DiscoveryResultSchema).
type Result struct {
	SchemaVersion   int       `json:"schemaVersion"`
	Status          string    `json:"status"`
	Provider        string    `json:"provider"`
	ProviderVersion string    `json:"providerVersion"`
	Execution       Execution `json:"execution"`
	Coverage        Coverage  `json:"coverage"`
	Records         []Record  `json:"records"`
	Diagnostics     []string  `json:"diagnostics"`
}

// Execution is the structured execution record.
type Execution struct {
	Argv            []string `json:"argv"`
	ExitCode        *int     `json:"exitCode"`
	ExitDescription string   `json:"exitDescription"`
	DurationMs      int64    `json:"durationMs"`
	StdoutBytes     int      `json:"stdoutBytes"`
	StderrBytes     int      `json:"stderrBytes"`
	Truncated       bool     `json:"truncated"`
	TimedOut        bool     `json:"timedOut"`
	SpawnError      string   `json:"spawnError"`
}

// Coverage counts units of work attempted by the provider.
type Coverage struct {
	Attempted   int `json:"attempted"`
	Succeeded   int `json:"succeeded"`
	Failed      int `json:"failed"`
	Skipped     int `json:"skipped"`
	Unavailable int `json:"unavailable"`
}

// Record is a discriminated union of discovery records.
type Record struct {
	Type string `json:"type"`
	// HOST_OBSERVATION
	Host      string   `json:"host,omitempty"`
	Source    string   `json:"source,omitempty"`
	Provider  string   `json:"provider,omitempty"`
	Status    string   `json:"status,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Notes     string   `json:"notes,omitempty"`
	// DNS_RECORD
	Name       string `json:"name,omitempty"`
	RecordType string `json:"recordType,omitempty"`
	Value      string `json:"value,omitempty"`
	TTL        *int   `json:"ttl,omitempty"`
	Resolver   string `json:"resolver,omitempty"`
	Error      string `json:"error,omitempty"`
	// IP_METADATA
	IP          string   `json:"ip,omitempty"`
	Prefix      *string  `json:"prefix,omitempty"`
	ASN         *int     `json:"asn,omitempty"`
	ASNOrg      *string  `json:"asnOrg,omitempty"`
	NetworkName *string  `json:"networkName,omitempty"`
	Country     *string  `json:"country,omitempty"`
	Confidence  float64  `json:"confidence,omitempty"`
	Limitations []string `json:"limitations,omitempty"`
	// HTTP_OBSERVATION
	URL  string       `json:"url,omitempty"`
	HTTP *HTTPDetails `json:"http,omitempty"`
	// TECHNOLOGY
	Technology *TechDetails `json:"technology,omitempty"`
	// URL_OBSERVATION
	CanonicalURL    string              `json:"canonicalUrl,omitempty"`
	Method          string              `json:"method,omitempty"`
	Depth           int                 `json:"depth,omitempty"`
	StatusCode      *int                `json:"statusCode,omitempty"`
	Classifications []UrlClassification `json:"classifications,omitempty"`
	Parameters      []UrlParameter      `json:"parameters,omitempty"`
	// ScriptRef marks a URL referenced by a <script src> attribute (extensionless JS support).
	ScriptRef bool `json:"scriptRef,omitempty"`
	// ParentURL is the HTML document that referenced this URL, for provenance.
	ParentURL string `json:"parentUrl,omitempty"`
	// JS_ARTIFACT
	Artifact *JsArtifactInfo `json:"artifact,omitempty"`
	// SOURCE_MAP
	SourceMap *SourceMapInfo `json:"sourceMap,omitempty"`
	// API_SPEC
	ApiSpec *ApiSpecInfo `json:"apiSpec,omitempty"`
	// API_ENDPOINT
	Endpoint *ApiEndpoint `json:"endpoint,omitempty"`
	// SECURITY_METADATA
	Security *SecurityMetadataInfo `json:"security,omitempty"`
	// SECRET_CANDIDATE
	Secret *SecretCandidateInfo `json:"secret,omitempty"`
	// SECRET_SCAN_ARTIFACT
	SecretScan *SecretScanArtifactInfo `json:"secretScan,omitempty"`
	// TAKEOVER_CANDIDATE
	Takeover *TakeoverInfo `json:"takeover,omitempty"`
	// LOGIN_INTERFACE
	Login *LoginInterfaceInfo `json:"login,omitempty"`
	// PORT_OBSERVATION
	Port *PortInfo `json:"port,omitempty"`
	// TEMPLATE_FINDING
	Template *TemplateInfo `json:"template,omitempty"`
	// CONTENT_DISCOVERY
	Content *ContentInfo `json:"content,omitempty"`
}

// ContentInfo is a path on an in-scope origin that answered differently from a missing path. It
// records only metadata: the response body is inspected in memory for a marker and never kept.
type ContentInfo struct {
	Path         string  `json:"path"`
	Category     string  `json:"category"`
	Status       string  `json:"status"`
	Severity     string  `json:"severity"`
	Confidence   float64 `json:"confidence"`
	HTTPStatus   int     `json:"httpStatus"`
	ContentSize  int     `json:"contentLength"`
	ContentType  string  `json:"contentType"`
	Title        string  `json:"title"`
	Evidence     string  `json:"evidence"`
	EvidenceType string  `json:"evidenceType"`
}

// TemplateInfo is a template match from a template-based checker. Severity is the template
// author's rating if the issue is real; a match is a signature detection, not a verified finding.
type TemplateInfo struct {
	TemplateID   string   `json:"templateId"`
	Name         string   `json:"name"`
	Severity     string   `json:"severity"`
	Description  string   `json:"description"`
	Tags         []string `json:"tags"`
	References   []string `json:"references"`
	MatcherName  string   `json:"matcherName"`
	Extracted    []string `json:"extracted"`
	TemplateType string   `json:"templateType"`
	Confidence   float64  `json:"confidence"`
}

// PortInfo is a TCP port observed on an address that resolves from an in-scope host. Product and
// version are the scanner's service-detection claims, not verified facts.
type PortInfo struct {
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	State      string  `json:"state"`
	Service    string  `json:"service"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	ExtraInfo  string  `json:"extraInfo"`
	TLS        bool    `json:"tls"`
	Confidence float64 `json:"confidence"`
}

// LoginInterfaceInfo is a discovered administrative login or hosting-control-panel interface.
// It records only what was observed with an unauthenticated GET; no credentials are submitted.
type LoginInterfaceInfo struct {
	Kind         string  `json:"kind"`
	Status       string  `json:"status"`
	Confidence   float64 `json:"confidence"`
	FinalURL     string  `json:"finalUrl"`
	HTTPStatus   *int    `json:"httpStatus"`
	Title        string  `json:"title"`
	Evidence     string  `json:"evidence"`
	EvidenceType string  `json:"evidenceType"`
}

// TakeoverInfo is a potential subdomain-takeover candidate (never a confirmed takeover).
type TakeoverInfo struct {
	Host         string  `json:"host"`
	CNAME        string  `json:"cname"`
	Service      string  `json:"service"`
	Status       string  `json:"status"`
	Confidence   float64 `json:"confidence"`
	HTTPStatus   *int    `json:"httpStatus"`
	Evidence     string  `json:"evidence"`
	EvidenceType string  `json:"evidenceType"`
}

// SecretCandidateInfo is a redacted potential-secret finding. The raw matched value is never held
// in this structure — only a redacted snippet and a keyed fingerprint.
type SecretCandidateInfo struct {
	RuleID            string  `json:"ruleId"`
	Category          string  `json:"category"`
	Status            string  `json:"status"`
	Confidence        float64 `json:"confidence"`
	ArtifactURL       string  `json:"artifactUrl"`
	Host              string  `json:"host"`
	Location          string  `json:"location"`
	RedactedSnippet   string  `json:"redactedSnippet"`
	Fingerprint       string  `json:"fingerprint"`
	Occurrences       int     `json:"occurrences"`
	Rationale         string  `json:"rationale"`
	SuppressionReason string  `json:"suppressionReason"`
}

// SecretScanArtifactInfo is the per-artifact outcome of a secret scan.
type SecretScanArtifactInfo struct {
	ArtifactURL   string `json:"artifactUrl"`
	Host          string `json:"host"`
	Status        string `json:"status"`
	FindingsCount int    `json:"findingsCount"`
	RawBytes      int    `json:"rawBytes"`
	HMACKeyed     bool   `json:"hmacKeyed"`
	Error         string `json:"error"`
}

// SecurityMetadataInfo is a single security-metadata observation.
type SecurityMetadataInfo struct {
	Category     string         `json:"category"`
	Name         string         `json:"name"`
	Status       string         `json:"status"`
	Observed     bool           `json:"observed"`
	Value        string         `json:"value"`
	Detail       map[string]any `json:"detail"`
	Consistent   *bool          `json:"consistent"`
	Evidence     string         `json:"evidence"`
	EvidenceType string         `json:"evidenceType"`
}

// JsArtifactInfo describes a retrieved (or failed) JavaScript artifact.
type JsArtifactInfo struct {
	URL             string `json:"url"`
	CanonicalURL    string `json:"canonicalUrl"`
	ContentHash     string `json:"contentHash"`
	ContentType     string `json:"contentType"`
	SizeBytes       int    `json:"sizeBytes"`
	SourceURL       string `json:"sourceUrl"`
	DiscoveryMethod string `json:"discoveryMethod"`
	Status          string `json:"status"`
	Error           string `json:"error"`
	Truncated       bool   `json:"truncated"`
}

// SourceMapInfo describes a discovered source map.
type SourceMapInfo struct {
	JsURL        string   `json:"jsUrl"`
	SourceMapURL string   `json:"sourceMapUrl"`
	Status       string   `json:"status"`
	SourcesCount int      `json:"sourcesCount"`
	Sources      []string `json:"sources"`
	SourceRoot   string   `json:"sourceRoot"`
	HasContent   bool     `json:"hasContent"`
	Error        string   `json:"error"`
}

// ApiSpecInfo describes a parsed (or failed) API specification.
type ApiSpecInfo struct {
	URL             string   `json:"url"`
	SpecVersion     string   `json:"specVersion"`
	Title           string   `json:"title"`
	Format          string   `json:"format"`
	Servers         []string `json:"servers"`
	PathCount       int      `json:"pathCount"`
	OperationCount  int      `json:"operationCount"`
	SecuritySchemes []string `json:"securitySchemes"`
	UnresolvedRefs  int      `json:"unresolvedRefs"`
	ParseStatus     string   `json:"parseStatus"`
	Error           string   `json:"error"`
}

// ApiEndpoint is a method-aware API endpoint candidate or documented endpoint.
type ApiEndpoint struct {
	Method        string         `json:"method"`
	Origin        string         `json:"origin"`
	Path          string         `json:"path"`
	URL           string         `json:"url"`
	DiscoveredVia string         `json:"discoveredVia"`
	Documented    bool           `json:"documented"`
	Resolved      bool           `json:"resolved"`
	OperationID   string         `json:"operationId"`
	Tags          []string       `json:"tags"`
	Parameters    []ApiParameter `json:"parameters"`
	ContentTypes  []string       `json:"contentTypes"`
	AuthSchemes   []string       `json:"authSchemes"`
	SourceURL     string         `json:"sourceUrl"`
	Evidence      string         `json:"evidence"`
	EvidenceType  string         `json:"evidenceType"`
}

// ApiParameter is a documented or inferred endpoint parameter.
type ApiParameter struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Required bool   `json:"required"`
	Type     string `json:"type"`
	Evidence string `json:"evidence"`
}

// UrlClassification is a single reconnaissance classification hypothesis.
type UrlClassification struct {
	Category     string  `json:"category"`
	Confidence   float64 `json:"confidence"`
	EvidenceType string  `json:"evidenceType"`
	Evidence     string  `json:"evidence"`
}

// UrlParameter is a query parameter with its inferred roles.
type UrlParameter struct {
	Name  string         `json:"name"`
	Roles []UrlParamRole `json:"roles"`
}

// UrlParamRole is one inferred role for a query parameter.
type UrlParamRole struct {
	Role       string  `json:"role"`
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
}

// HTTPDetails holds the reconnaissance metadata for an HTTP probe.
type HTTPDetails struct {
	FinalURL      string            `json:"finalUrl"`
	StatusCode    *int              `json:"statusCode"`
	StatusText    string            `json:"statusText"`
	ContentType   string            `json:"contentType"`
	Title         string            `json:"title"`
	Headers       map[string]string `json:"headers"`
	RedirectChain []RedirectHop     `json:"redirectChain"`
	TLS           *TLSInfo          `json:"tls"`
	ProbeStatus   string            `json:"probeStatus"`
	Error         string            `json:"error"`
	BodyTruncated bool              `json:"bodyTruncated"`
}

// RedirectHop is a single hop in a redirect chain.
type RedirectHop struct {
	From       string `json:"from"`
	To         string `json:"to"`
	StatusCode *int   `json:"statusCode"`
}

// TLSInfo is the subset of TLS certificate metadata retained for reconnaissance.
type TLSInfo struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"notBefore"`
	NotAfter  string   `json:"notAfter"`
	SHA256    string   `json:"sha256"`
	Protocol  string   `json:"protocol"`
	SANs      []string `json:"sans"`
}

// TechDetails is a single evidence-backed technology fingerprint.
type TechDetails struct {
	Name         string  `json:"name"`
	Category     string  `json:"category"`
	EvidenceType string  `json:"evidenceType"`
	Evidence     string  `json:"evidence"`
	Confidence   float64 `json:"confidence"`
}

const (
	TypeHostObservation    = "HOST_OBSERVATION"
	TypeDNSRecord          = "DNS_RECORD"
	TypeIPMetadata         = "IP_METADATA"
	TypeHTTPObservation    = "HTTP_OBSERVATION"
	TypeTechnology         = "TECHNOLOGY"
	TypeURLObservation     = "URL_OBSERVATION"
	TypeJSArtifact         = "JS_ARTIFACT"
	TypeSourceMap          = "SOURCE_MAP"
	TypeApiSpec            = "API_SPEC"
	TypeApiEndpoint        = "API_ENDPOINT"
	TypeSecurityMetadata   = "SECURITY_METADATA"
	TypeSecretCandidate    = "SECRET_CANDIDATE"
	TypeSecretScanArtifact = "SECRET_SCAN_ARTIFACT"
	TypeTakeoverCandidate  = "TAKEOVER_CANDIDATE"
	TypeLoginInterface     = "LOGIN_INTERFACE"
	TypePortObservation    = "PORT_OBSERVATION"
	TypeTemplateFinding    = "TEMPLATE_FINDING"
	TypeContentDiscovery   = "CONTENT_DISCOVERY"
)

// Login-interface kinds and statuses. DETECTED means a concrete marker was observed; POSSIBLE
// means only weaker evidence (usually an auth-required status on a known admin path). Neither is
// a vulnerability claim.
const (
	LoginKindAdmin  = "ADMIN"
	LoginKindCpanel = "CPANEL"

	LoginDetected = "DETECTED"
	LoginPossible = "POSSIBLE"
)

// Subdomain-takeover candidate statuses (never a confirmed takeover).
const (
	TakeoverSuspected    = "SUSPECTED"
	TakeoverCandidate    = "CANDIDATE"
	TakeoverNotVuln      = "NOT_VULNERABLE"
	TakeoverInconclusive = "INCONCLUSIVE"
)

// Secret finding statuses (no VALIDATED/ACTIVE — verification is not permitted).
const (
	SecretCandidate    = "CANDIDATE"
	SecretHighConf     = "HIGH_CONFIDENCE"
	SecretSuppressed   = "SUPPRESSED"
	SecretAnalysisFail = "ANALYSIS_FAILED"
)

// Secret scan artifact statuses.
const (
	SecretArtifactAnalyzed       = "ANALYZED"
	SecretArtifactAnalysisFailed = "ANALYSIS_FAILED"
	SecretArtifactSkipped        = "SKIPPED"
	SecretArtifactOversized      = "OVERSIZED"
)

// Security metadata categories.
const (
	CatTLS         = "TLS"
	CatHeader      = "HEADER"
	CatCookie      = "COOKIE"
	CatCORS        = "CORS"
	CatHSTS        = "HSTS"
	CatContentType = "CONTENT_TYPE"
)

// Metadata observation states (never treat NOT_OBSERVED as "control absent").
const (
	MetaObserved         = "OBSERVED"
	MetaInferred         = "INFERRED"
	MetaInconsistent     = "INCONSISTENT"
	MetaNotObserved      = "NOT_OBSERVED"
	MetaUnknown          = "UNKNOWN"
	MetaCollectionFailed = "COLLECTION_FAILED"
)

// Artifact retrieval statuses.
const (
	ArtifactRetrieved      = "RETRIEVED"
	ArtifactNotFound       = "NOT_FOUND"
	ArtifactError          = "ERROR"
	ArtifactSkipped        = "SKIPPED"
	ArtifactOversized      = "OVERSIZED"
	ArtifactMismatchedMime = "MISMATCHED_MIME"
)

// Endpoint discovery sources.
const (
	ViaJS   = "JS"
	ViaSpec = "SPEC"
	ViaHTTP = "HTTP"
)

// URL collection methods.
const (
	MethodCrawl   = "CRAWL"
	MethodPassive = "PASSIVE"
	MethodRobots  = "ROBOTS"
	MethodSitemap = "SITEMAP"
	MethodSeed    = "SEED"
)

// HTTP probe statuses.
const (
	ProbeOK               = "OK"
	ProbeRedirectDenied   = "REDIRECT_DENIED"
	ProbeTooManyRedirects = "TOO_MANY_REDIRECTS"
	ProbeTimeout          = "TIMEOUT"
	ProbeConnectionError  = "CONNECTION_ERROR"
	ProbeTLSError         = "TLS_ERROR"
	ProbeOversized        = "OVERSIZED"
	ProbeBlockedAddress   = "BLOCKED_ADDRESS"
	ProbeError            = "ERROR"
)

// Statuses.
const (
	StatusSucceeded         = "SUCCEEDED"
	StatusPartial           = "PARTIAL"
	StatusFailed            = "FAILED"
	StatusSkipped           = "SKIPPED"
	StatusBlocked           = "BLOCKED"
	StatusCancelled         = "CANCELLED"
	StatusSourceUnavailable = "SOURCE_UNAVAILABLE"
)

// Host statuses.
const (
	HostDiscovered = "DISCOVERED"
	HostResolved   = "RESOLVED"
	HostUnresolved = "UNRESOLVED"
	HostWildcard   = "WILDCARD"
)
