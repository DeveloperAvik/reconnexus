// builtin-static: robots.txt and sitemap discovery.

package discovery

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type builtinStatic struct{}

func (builtinStatic) Name() string            { return "builtin-static" }
func (builtinStatic) Kind() string            { return "URL_COLLECTION" }
func (builtinStatic) Capability() string      { return "ACTIVE_HTTP" }
func (builtinStatic) NetworkBehavior() string { return "ACTIVE" }

func (builtinStatic) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	seeds := job.Inputs.SeedURLs
	if len(seeds) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no origins for robots/sitemap discovery")
		return res, nil
	}
	timeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultCrawlTimeoutMs * time.Millisecond
	}
	maxBytes := job.Limits.MaxArtifactBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}
	transport, err := pc.buildTransport(job)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build transport: "+err.Error())
		return res, nil
	}
	client, _ := newGuardedClient(transport, pc.Engine, timeout, job.MaxRedirects)

	var records []Record
	origins := map[string]struct{}{}
	for _, s := range seeds {
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		origins[strings.ToLower(u.Scheme)+"://"+strings.ToLower(u.Host)] = struct{}{}
	}
	res.Coverage.Attempted = len(origins)

	sitemaps := map[string]struct{}{}
	for origin := range origins {
		if ctx.Err() != nil {
			break
		}
		robotsURL := origin + "/robots.txt"
		if _, _, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", robotsURL); bad || !ok {
			res.Coverage.Skipped++
			continue
		}
		body, status, ferr := fetchText(ctx, client, pc.Limiter, robotsURL, maxBytes)
		if ferr != nil {
			res.Coverage.Failed++
			res.Diagnostics = append(res.Diagnostics, "robots.txt "+origin+": "+truncate(ferr.Error(), 120))
			continue
		}
		if status == 200 {
			for _, line := range strings.Split(body, "\n") {
				line = strings.TrimSpace(line)
				low := strings.ToLower(line)
				if strings.HasPrefix(low, "sitemap:") {
					sm := strings.TrimSpace(line[len("sitemap:"):])
					if _, _, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", sm); ok && !bad {
						sitemaps[sm] = struct{}{}
					}
				} else if strings.HasPrefix(low, "disallow:") || strings.HasPrefix(low, "allow:") {
					pth := strings.TrimSpace(line[strings.Index(line, ":")+1:])
					if pth == "" || pth == "/" {
						continue
					}
					cand := origin + pth
					// Robots rules are not authorization; recorded as candidates only.
					c, h, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", cand)
					if ok && !bad {
						records = append(records, buildURLRecord(cand, c, h, MethodRobots, "builtin-static", "robots", 0, nil))
					}
				}
			}
			res.Coverage.Succeeded++
		} else if status >= 400 && status < 500 {
			// A missing robots.txt (typically 404) is a complete, normal answer, not a provider
			// failure. Treat 4xx as not-found coverage so it cannot make the whole stage PARTIAL.
			res.Coverage.Skipped++
			res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("robots.txt %s not available (HTTP %d)", origin, status))
		} else {
			res.Coverage.Failed++
			res.Diagnostics = append(res.Diagnostics, fmt.Sprintf("robots.txt %s returned %d", origin, status))
		}
	}

	// Default sitemap if none declared.
	for origin := range origins {
		if len(sitemaps) == 0 {
			sitemaps[origin+"/sitemap.xml"] = struct{}{}
		}
	}

	queue := stringKeys(sitemaps)
	seenSitemaps := map[string]struct{}{}
	urlCount := 0
	for len(queue) > 0 && len(seenSitemaps) < maxSitemaps && urlCount < maxStaticURLs && ctx.Err() == nil {
		sm := queue[0]
		queue = queue[1:]
		if _, seen := seenSitemaps[sm]; seen {
			continue
		}
		seenSitemaps[sm] = struct{}{}
		if _, _, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", sm); !ok || bad {
			res.Coverage.Skipped++
			continue
		}
		body, status, ferr := fetchText(ctx, client, pc.Limiter, sm, maxBytes)
		if ferr != nil {
			res.Coverage.Failed++
			continue
		}
		if status != 200 {
			// A missing sitemap (404/410) or an access denial is a normal absence, not a provider
			// failure. Only a server/transport error makes the collection incomplete.
			if status >= 400 && status < 500 {
				res.Coverage.Skipped++
			} else {
				res.Coverage.Failed++
			}
			continue
		}
		locs, childSitemaps, perr := parseSitemap(body)
		if perr != nil {
			res.Diagnostics = append(res.Diagnostics, "malformed sitemap "+sm+": "+perr.Error())
			continue
		}
		for _, child := range childSitemaps {
			if _, _, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", child); ok && !bad {
				queue = append(queue, child)
			}
		}
		for _, loc := range locs {
			if urlCount >= maxStaticURLs {
				break
			}
			c, h, ok, bad := authorizeURL(pc.Engine, "ACTIVE_HTTP", loc)
			if !ok || bad {
				if !bad {
					res.Coverage.Skipped++
				}
				continue
			}
			records = append(records, buildURLRecord(loc, c, h, MethodSitemap, "builtin-static", "sitemap", 0, nil))
			urlCount++
		}
	}

	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	res.Records = records
	return res, nil
}

func fetchText(ctx context.Context, client *http.Client, limiter *rateLimiter, rawURL string, maxBytes int) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "reconnexus/0.4 (+https://github.com/anomalyco/opencode)")
	resp, err := doRequest(ctx, client, limiter, req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _, _ := readBounded(resp.Body, maxBytes)
	return body, resp.StatusCode, nil
}

type sitemapDoc struct {
	XMLName  xml.Name
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

func parseSitemap(body string) (locs []string, childSitemaps []string, err error) {
	var doc sitemapDoc
	if err := xml.Unmarshal([]byte(strings.TrimSpace(body)), &doc); err != nil {
		return nil, nil, err
	}
	switch strings.ToLower(doc.XMLName.Local) {
	case "sitemapindex":
		for _, s := range doc.Sitemaps {
			if s.Loc != "" {
				childSitemaps = append(childSitemaps, strings.TrimSpace(s.Loc))
			}
		}
	case "urlset":
		for _, u := range doc.URLs {
			if u.Loc != "" {
				locs = append(locs, strings.TrimSpace(u.Loc))
			}
		}
	default:
		return nil, nil, errors.New("unrecognized sitemap root element: " + doc.XMLName.Local)
	}
	return locs, childSitemaps, nil
}
