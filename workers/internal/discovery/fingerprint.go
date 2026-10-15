package discovery

import (
	"fmt"
	"strings"
)

// fingerprintInput is the evidence available to a signature. All header keys are lowercase.
type fingerprintInput struct {
	Headers   map[string]string
	Body      string // lowercased, already size-limited
	Title     string
	Cookies   []string // cookie NAMES only (never values)
	TLSIssuer string
}

type signature struct {
	name         string
	category     string
	evidenceType string
	confidence   float64
	detect       func(in fingerprintInput) (string, bool)
}

func hdr(in fingerprintInput, name string) string { return in.Headers[name] }

func headerHas(in fingerprintInput, name, needle string) (string, bool) {
	v := hdr(in, name)
	if v != "" && strings.Contains(strings.ToLower(v), needle) {
		return fmt.Sprintf("%s: %s", name, v), true
	}
	return "", false
}

func headerPresent(in fingerprintInput, name string) (string, bool) {
	if v := hdr(in, name); v != "" {
		return fmt.Sprintf("%s: %s", name, v), true
	}
	return "", false
}

func bodyHas(in fingerprintInput, needle string) (string, bool) {
	if strings.Contains(in.Body, needle) {
		return "body contains " + needle, true
	}
	return "", false
}

func titleHas(in fingerprintInput, needle string) (string, bool) {
	if in.Title != "" && strings.Contains(strings.ToLower(in.Title), needle) {
		return "title ~ " + needle, true
	}
	return "", false
}

func cookieHas(in fingerprintInput, name string) (string, bool) {
	for _, c := range in.Cookies {
		if c == name {
			return "cookie " + name, true
		}
	}
	return "", false
}

func issuerHas(in fingerprintInput, needle string) (string, bool) {
	if in.TLSIssuer != "" && strings.Contains(strings.ToLower(in.TLSIssuer), needle) {
		return "TLS issuer ~ " + needle, true
	}
	return "", false
}

func anyOf(dets ...func(fingerprintInput) (string, bool)) func(fingerprintInput) (string, bool) {
	return func(in fingerprintInput) (string, bool) {
		for _, d := range dets {
			if ev, ok := d(in); ok {
				return ev, true
			}
		}
		return "", false
	}
}

// signatures is a deterministic, evidence-backed table. Signatures require specific markers;
// generic strings ("welcome", "login") never assert a technology by themselves.
var signatures = []signature{
	// Web servers
	{"nginx", "WEB_SERVER", "HEADER", 0.9, func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "nginx") }},
	{"Apache HTTP Server", "WEB_SERVER", "HEADER", 0.9, func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "apache") }},
	{"Microsoft IIS", "WEB_SERVER", "HEADER", 0.9, func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "iis") }},
	{"LiteSpeed", "WEB_SERVER", "HEADER", 0.9, func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "litespeed") }},
	{"Caddy", "WEB_SERVER", "HEADER", 0.9, func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "caddy") }},
	{"OpenResty", "WEB_SERVER", "HEADER", 0.9, func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "openresty") }},
	{"gunicorn", "WEB_SERVER", "HEADER", 0.85, func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "gunicorn") }},
	{"Envoy", "WEB_SERVER", "HEADER", 0.85, anyOf(
		func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "envoy") },
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-envoy-upstream-service-time") },
	)},
	{"Tomcat", "WEB_SERVER", "HEADER", 0.8, func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "coyote") }},
	{"Varnish", "WEB_SERVER", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerHas(in, "via", "varnish") },
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-varnish") },
	)},

	// Frameworks / languages
	{"PHP", "FRAMEWORK", "HEADER", 0.95, anyOf(
		func(in fingerprintInput) (string, bool) { return headerHas(in, "x-powered-by", "php") },
		func(in fingerprintInput) (string, bool) { return cookieHas(in, "phpsessid") },
	)},
	{"ASP.NET", "FRAMEWORK", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerHas(in, "x-powered-by", "asp.net") },
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-aspnet-version") },
		func(in fingerprintInput) (string, bool) { return cookieHas(in, "asp.net_sessionid") },
	)},
	{"Express", "FRAMEWORK", "HEADER", 0.95, func(in fingerprintInput) (string, bool) { return headerHas(in, "x-powered-by", "express") }},
	{"Django", "FRAMEWORK", "HTML_MARKER", 0.8, anyOf(
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "csrfmiddlewaretoken") },
		func(in fingerprintInput) (string, bool) { return cookieHas(in, "csrftoken") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "/static/admin/") },
	)},
	{"Ruby on Rails", "FRAMEWORK", "HTML_MARKER", 0.8, anyOf(
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "csrf-param") },
		func(in fingerprintInput) (string, bool) { return cookieHas(in, "_rails") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "x-powered-by", "phusion passenger") },
	)},
	{"Laravel", "FRAMEWORK", "COOKIE", 0.85, anyOf(
		func(in fingerprintInput) (string, bool) { return cookieHas(in, "laravel_session") },
		func(in fingerprintInput) (string, bool) { return cookieHas(in, "xsrf-token") },
	)},
	{"Java (servlet container)", "FRAMEWORK", "COOKIE", 0.6, func(in fingerprintInput) (string, bool) { return cookieHas(in, "jsessionid") }},
	{"Spring", "FRAMEWORK", "HEADER", 0.85, func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-application-context") }},

	// CMS
	{"WordPress", "CMS", "HTML_MARKER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "wp-content/") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "wp-includes/") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "x-powered-by", "wordpress") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "/wp-json") },
	)},
	{"Drupal", "CMS", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-drupal-cache") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "x-generator", "drupal") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "sites/default/files") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "drupal.settings") },
	)},
	{"Joomla", "CMS", "HTML_MARKER", 0.85, anyOf(
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "/media/jui/") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "x-generator", "joomla") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "com_content") },
	)},
	{"Shopify", "CMS", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-shopify-stage") },
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-shopid") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "shopify") },
	)},
	{"Magento", "CMS", "COOKIE", 0.8, anyOf(
		func(in fingerprintInput) (string, bool) { return cookieHas(in, "frontend") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "mage/cookies") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "x-magento") },
	)},
	{"Ghost", "CMS", "HTML_MARKER", 0.85, anyOf(
		func(in fingerprintInput) (string, bool) { return headerHas(in, "x-generator", "ghost") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "ghost-sdk") },
	)},

	// Frontend frameworks
	{"Next.js", "FRONTEND_FRAMEWORK", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerHas(in, "x-powered-by", "next.js") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "__next_data__") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "/_next/static/") },
	)},
	{"React", "FRONTEND_FRAMEWORK", "HTML_MARKER", 0.85, anyOf(
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "data-reactroot") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "data-reactid") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "__react") },
	)},
	{"Angular", "FRONTEND_FRAMEWORK", "HTML_MARKER", 0.85, anyOf(
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "ng-version=") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "ng-app") },
	)},
	{"Vue.js", "FRONTEND_FRAMEWORK", "HTML_MARKER", 0.75, anyOf(
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "data-v-") },
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "__vue__") },
	)},
	{"jQuery", "FRONTEND_FRAMEWORK", "HTML_MARKER", 0.7, func(in fingerprintInput) (string, bool) { return bodyHas(in, "jquery.min.js") }},

	// CDN / WAF
	{"Cloudflare", "CDN_WAF", "HEADER", 0.95, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "cf-ray") },
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "cf-cache-status") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "cloudflare") },
		func(in fingerprintInput) (string, bool) { return issuerHas(in, "cloudflare") },
	)},
	{"Amazon CloudFront", "CDN_WAF", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-amz-cf-id") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "via", "cloudfront") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "cloudfront") },
	)},
	{"Fastly", "CDN_WAF", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-fastly-request-id") },
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-served-by") },
	)},
	{"Akamai", "CDN_WAF", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-akamai-transformed") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "akamaighost") },
	)},
	{"Azure Front Door", "CDN_WAF", "HEADER", 0.9, func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-azure-ref") }},
	{"Sucuri", "CDN_WAF", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-sucuri-id") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "sucuri") },
	)},
	{"Imperva Incapsula", "CDN_WAF", "COOKIE", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-iinfo") },
		func(in fingerprintInput) (string, bool) { return cookieHas(in, "incap_ses_1") },
	)},
	{"Vercel", "CDN_WAF", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-vercel-id") },
		func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "vercel") },
	)},

	// API gateways
	{"Kong", "API_GATEWAY", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerHas(in, "server", "kong") },
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-kong-upstream-latency") },
	)},
	{"AWS API Gateway", "API_GATEWAY", "HEADER", 0.9, func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-amz-apigw-id") }},

	// Login / documentation / dev services
	{"Login interface", "LOGIN_INTERFACE", "TITLE", 0.5, anyOf(
		func(in fingerprintInput) (string, bool) { return titleHas(in, "log in") },
		func(in fingerprintInput) (string, bool) { return titleHas(in, "sign in") },
		func(in fingerprintInput) (string, bool) { return titleHas(in, "login") },
	)},
	{"Swagger UI", "DOCUMENTATION", "HTML_MARKER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "swagger-ui") },
		func(in fingerprintInput) (string, bool) { return titleHas(in, "swagger ui") },
	)},
	{"Redoc", "DOCUMENTATION", "HTML_MARKER", 0.85, func(in fingerprintInput) (string, bool) { return bodyHas(in, "redoc") }},
	{"Jenkins", "DEV_SERVICE", "HEADER", 0.9, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "x-jenkins") },
		func(in fingerprintInput) (string, bool) { return titleHas(in, "[jenkins]") },
	)},
	{"Grafana", "DEV_SERVICE", "HTML_MARKER", 0.8, anyOf(
		func(in fingerprintInput) (string, bool) { return bodyHas(in, "grafana-app") },
		func(in fingerprintInput) (string, bool) { return titleHas(in, "grafana") },
	)},
	{"Kibana", "DEV_SERVICE", "HEADER", 0.85, anyOf(
		func(in fingerprintInput) (string, bool) { return headerPresent(in, "kbn-name") },
		func(in fingerprintInput) (string, bool) { return titleHas(in, "kibana") },
	)},
	{"phpMyAdmin", "DEV_SERVICE", "HTML_MARKER", 0.85, func(in fingerprintInput) (string, bool) { return bodyHas(in, "pma_password") }},
	{"Prometheus", "DEV_SERVICE", "TITLE", 0.7, func(in fingerprintInput) (string, bool) { return titleHas(in, "prometheus") }},
}

// Fingerprint returns evidence-backed technology hypotheses. Multiple hypotheses may apply.
func Fingerprint(in fingerprintInput) []TechDetails {
	var out []TechDetails
	for _, sig := range signatures {
		if ev, ok := sig.detect(in); ok {
			out = append(out, TechDetails{
				Name:         sig.name,
				Category:     sig.category,
				EvidenceType: sig.evidenceType,
				Evidence:     ev,
				Confidence:   sig.confidence,
			})
		}
	}
	return out
}
