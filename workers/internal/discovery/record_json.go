package discovery

import "encoding/json"

// recordEnvelope is Record without its MarshalJSON method, used to serialize the record's own
// framing fields without recursing.
type recordEnvelope Record

// flatPayloads returns the nested payloads whose JSON contract is flat on the record object.
// HTTP_OBSERVATION and TECHNOLOGY are deliberately absent: the contract nests those under
// `http` and `technology`, so they are marshalled as-is.
func (r *Record) flatPayloads() []any {
	out := make([]any, 0, 2)
	if r.Artifact != nil {
		out = append(out, r.Artifact)
	}
	if r.SourceMap != nil {
		out = append(out, r.SourceMap)
	}
	if r.ApiSpec != nil {
		out = append(out, r.ApiSpec)
	}
	if r.Endpoint != nil {
		out = append(out, r.Endpoint)
	}
	if r.Security != nil {
		out = append(out, r.Security)
	}
	if r.Secret != nil {
		out = append(out, r.Secret)
	}
	if r.SecretScan != nil {
		out = append(out, r.SecretScan)
	}
	if r.Takeover != nil {
		out = append(out, r.Takeover)
	}
	if r.Login != nil {
		out = append(out, r.Login)
	}
	if r.Port != nil {
		out = append(out, r.Port)
	}
	if r.Template != nil {
		out = append(out, r.Template)
	}
	if r.Content != nil {
		out = append(out, r.Content)
	}
	if r.CloudStorage != nil {
		out = append(out, r.CloudStorage)
	}
	return out
}

// MarshalJSON emits the record in the shape declared by packages/contracts/src/discovery.ts.
// JS_ARTIFACT, SOURCE_MAP, API_SPEC, API_ENDPOINT, SECURITY_METADATA, SECRET_CANDIDATE,
// SECRET_SCAN_ARTIFACT, TAKEOVER_CANDIDATE and LOGIN_INTERFACE carry their payload fields flat on
// the record; only HTTP_OBSERVATION and TECHNOLOGY nest theirs. The record's own fields win over
// the payload: they use `omitempty`, so only the ones a provider actually set are present, and
// framing (`url`, `provider`, `source`, …) is never overwritten by an unset payload field.
func (r Record) MarshalJSON() ([]byte, error) {
	payloads := r.flatPayloads()
	base := r
	base.Artifact = nil
	base.SourceMap = nil
	base.ApiSpec = nil
	base.Endpoint = nil
	base.Security = nil
	base.Secret = nil
	base.SecretScan = nil
	base.Takeover = nil
	base.Login = nil
	base.Port = nil
	base.Template = nil
	base.Content = nil
	base.CloudStorage = nil

	baseBytes, err := json.Marshal(recordEnvelope(base))
	if err != nil {
		return nil, err
	}
	if len(payloads) == 0 {
		return baseBytes, nil
	}

	merged := map[string]json.RawMessage{}
	for _, p := range payloads {
		pb, err := json.Marshal(p)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(pb, &merged); err != nil {
			return nil, err
		}
	}
	if err := json.Unmarshal(baseBytes, &merged); err != nil {
		return nil, err
	}
	return json.Marshal(merged)
}

// normalize replaces nil slices and maps with empty ones. Go marshals a nil slice or map as
// `null`, but the contract declares these fields as arrays and objects, so an un-normalized
// record (an HTTP probe that errored before any header was read, for example) is rejected by
// the control plane's schema validation and the whole provider run is lost.
func (r *Record) normalize() {
	if r.Addresses == nil {
		r.Addresses = []string{}
	}
	if r.Limitations == nil {
		r.Limitations = []string{}
	}
	if r.Classifications == nil {
		r.Classifications = []UrlClassification{}
	}
	if r.Parameters == nil {
		r.Parameters = []UrlParameter{}
	}
	for i := range r.Parameters {
		if r.Parameters[i].Roles == nil {
			r.Parameters[i].Roles = []UrlParamRole{}
		}
	}
	if r.HTTP != nil {
		if r.HTTP.Headers == nil {
			r.HTTP.Headers = map[string]string{}
		}
		if r.HTTP.RedirectChain == nil {
			r.HTTP.RedirectChain = []RedirectHop{}
		}
		if r.HTTP.TLS != nil && r.HTTP.TLS.SANs == nil {
			r.HTTP.TLS.SANs = []string{}
		}
	}
	if r.SourceMap != nil && r.SourceMap.Sources == nil {
		r.SourceMap.Sources = []string{}
	}
	if r.ApiSpec != nil {
		if r.ApiSpec.Servers == nil {
			r.ApiSpec.Servers = []string{}
		}
		if r.ApiSpec.SecuritySchemes == nil {
			r.ApiSpec.SecuritySchemes = []string{}
		}
	}
	if r.Endpoint != nil {
		if r.Endpoint.Tags == nil {
			r.Endpoint.Tags = []string{}
		}
		if r.Endpoint.Parameters == nil {
			r.Endpoint.Parameters = []ApiParameter{}
		}
		if r.Endpoint.ContentTypes == nil {
			r.Endpoint.ContentTypes = []string{}
		}
		if r.Endpoint.AuthSchemes == nil {
			r.Endpoint.AuthSchemes = []string{}
		}
	}
	if r.Template != nil {
		if r.Template.Tags == nil {
			r.Template.Tags = []string{}
		}
		if r.Template.References == nil {
			r.Template.References = []string{}
		}
		if r.Template.Extracted == nil {
			r.Template.Extracted = []string{}
		}
	}
	if r.Security != nil && r.Security.Detail == nil {
		r.Security.Detail = map[string]any{}
	}
}

// NormalizeRecords applies normalize to every record in place.
func NormalizeRecords(records []Record) {
	for i := range records {
		records[i].normalize()
	}
}
