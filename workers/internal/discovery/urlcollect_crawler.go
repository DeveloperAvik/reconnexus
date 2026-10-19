// builtin-crawler: bounded, scope-guarded HTML crawler.

package discovery

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/reconnexus/workers/internal/matching"
)

type builtinCrawler struct{}

func (builtinCrawler) Name() string            { return "builtin-crawler" }
func (builtinCrawler) Kind() string            { return "URL_COLLECTION" }
func (builtinCrawler) Capability() string      { return "CRAWL" }
func (builtinCrawler) NetworkBehavior() string { return "ACTIVE" }

func (builtinCrawler) Run(ctx context.Context, pc ProviderContext) (ProviderResult, error) {
	job := pc.Job
	res := ProviderResult{Coverage: Coverage{}}
	seeds := job.Inputs.SeedURLs
	if len(seeds) == 0 {
		res.StatusOverride = StatusSkipped
		res.Diagnostics = append(res.Diagnostics, "no seed URLs to crawl")
		return res, nil
	}
	maxDepth := job.Inputs.CrawlDepth
	if maxDepth <= 0 {
		maxDepth = defaultCrawlDepth
	}
	budget := job.Inputs.RequestBudget
	if budget <= 0 {
		budget = defaultRequestBudget
	}
	concurrency := job.Limits.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > 32 {
		concurrency = 32
	}
	timeout := time.Duration(job.RequestTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultCrawlTimeoutMs * time.Millisecond
	}
	maxBytes := job.Limits.MaxArtifactBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}
	maxRedirects := job.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 5
	}

	transport, err := pc.buildTransport(job)
	if err != nil {
		res.StatusOverride = StatusFailed
		res.Coverage.Failed = 1
		res.Diagnostics = append(res.Diagnostics, "cannot build crawler transport: "+err.Error())
		return res, nil
	}

	var mu sync.Mutex
	var records []Record
	emitted := map[string]int{}
	var diagnostics []string
	visited := map[string]struct{}{}
	var budgetUsed int

	// emitOrUpdate appends a record for a canonical URL the first time it is seen, and
	// updates the status code in place on later fetches. This keeps one observation per
	// canonical URL per provider run while preserving cross-provider provenance.
	emitOrUpdate := func(rec Record, status *int) {
		if idx, ok := emitted[rec.CanonicalURL]; ok {
			if status != nil {
				records[idx].StatusCode = status
			}
			// Upgrade provenance when the same canonical URL is later seen as a <script src>:
			// the JavaScript classification and parent document are strictly more informative.
			if rec.ScriptRef && !records[idx].ScriptRef {
				records[idx].ScriptRef = true
				records[idx].ParentURL = rec.ParentURL
				records[idx].Classifications = mergeScriptRefClassifications(records[idx].Classifications, rec.Classifications)
			}
			return
		}
		emitted[rec.CanonicalURL] = len(records)
		records = append(records, rec)
	}

	type item struct {
		raw   string
		depth int
	}
	var frontier []item
	for _, s := range seeds {
		canon, host, ok, bad := authorizeURL(pc.Engine, "CRAWL", s)
		if bad {
			res.Coverage.Failed++
			continue
		}
		if !ok {
			res.Coverage.Skipped++
			continue
		}
		if _, seen := visited[canon]; seen {
			continue
		}
		visited[canon] = struct{}{}
		frontier = append(frontier, item{raw: canon, depth: 0})
		mu.Lock()
		emitOrUpdate(buildURLRecord(s, canon, host, MethodSeed, "builtin-crawler", "seed", 0, nil), nil)
		mu.Unlock()
	}
	res.Coverage.Attempted = len(seeds)

	for depth := 0; depth <= maxDepth && len(frontier) > 0; depth++ {
		if ctx.Err() != nil {
			break
		}
		var next []item
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for _, it := range frontier {
			if ctx.Err() != nil || budgetUsed >= budget {
				break
			}
			mu.Lock()
			if budgetUsed >= budget {
				mu.Unlock()
				break
			}
			budgetUsed++
			mu.Unlock()
			wg.Add(1)
			sem <- struct{}{}
			go func(it item) {
				defer wg.Done()
				defer func() { <-sem }()
				client, _ := newGuardedClient(transport, pc.Engine, timeout, maxRedirects)
				req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, it.raw, nil)
				if rerr != nil {
					mu.Lock()
					diagnostics = append(diagnostics, "crawl request build failed: "+rerr.Error())
					mu.Unlock()
					return
				}
				req.Header.Set("User-Agent", "reconnexus/0.4 (+https://github.com/anomalyco/opencode)")
				resp, derr := doRequest(ctx, client, pc.Limiter, req)
				if derr != nil || resp == nil {
					mu.Lock()
					if derr != nil {
						diagnostics = append(diagnostics, fmt.Sprintf("crawl %s: %s", it.raw, truncate(derr.Error(), 160)))
					}
					mu.Unlock()
					return
				}
				defer resp.Body.Close()
				body, _, _ := readBounded(resp.Body, maxBytes)
				canon := it.raw
				if resp.Request != nil {
					if c, err := matching.CanonicalURL(resp.Request.URL.String()); err == nil {
						canon = c
					}
				}
				code := resp.StatusCode
				mu.Lock()
				emitOrUpdate(buildURLRecord(it.raw, canon, hostOf(canon), MethodCrawl, "builtin-crawler", "crawl", it.depth, &code), &code)
				mu.Unlock()
				if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
					return
				}
				// <script src> references first, so their classification is in place before the
				// generic link pass decides what to crawl. They become JavaScript candidates even
				// when the path is extensionless (a common bundler pattern), preserving the
				// parent-document provenance. They are not added to the crawl frontier below:
				// a script is not an HTML document, and Stage 07 retrieves it once with content
				// validation rather than the crawler fetching it twice.
				parent := resp.Request.URL.String()
				for _, sref := range extractScriptRefs(body, resp.Request.URL) {
					c, h, ok, bad := authorizeURL(pc.Engine, "CRAWL", sref)
					if bad || !ok {
						if !bad {
							mu.Lock()
							res.Coverage.Skipped++
							mu.Unlock()
						}
						continue
					}
					rec := buildURLRecord(sref, c, h, MethodCrawl, "builtin-crawler", "script-ref", it.depth+1, nil)
					if !markScriptRef(&rec, parent) {
						continue
					}
					mu.Lock()
					emitOrUpdate(rec, nil)
					mu.Unlock()
				}

				for _, link := range extractLinks(body, resp.Request.URL) {
					c, h, ok, bad := authorizeURL(pc.Engine, "CRAWL", link)
					if bad || !ok {
						if !bad {
							mu.Lock()
							res.Coverage.Skipped++
							mu.Unlock()
						}
						continue
					}
					mu.Lock()
					if _, seen := visited[c]; seen {
						mu.Unlock()
						continue
					}
					visited[c] = struct{}{}
					emitOrUpdate(buildURLRecord(link, c, h, MethodCrawl, "builtin-crawler", "crawl", it.depth+1, nil), nil)
					// Only links that could yield HTML are followed; static assets and scripts are
					// kept in the URL inventory but do not consume the crawl request budget.
					if it.depth+1 <= maxDepth && crawlable(records[emitted[c]]) {
						next = append(next, item{raw: c, depth: it.depth + 1})
					}
					mu.Unlock()
				}
			}(it)
		}
		wg.Wait()
		res.Coverage.Succeeded += len(frontier)
		res.Coverage.Attempted += len(frontier)
		frontier = next
	}

	res.Records = records
	res.Diagnostics = append(res.Diagnostics, diagnostics...)
	if ctx.Err() != nil {
		res.StatusOverride = StatusCancelled
	}
	return res, nil
}

// crawlable reports whether following a URL could yield further HTML links. Scripts, static assets
// and downloads cannot, so they are recorded in the URL inventory but do not spend the request
// budget or risk parsing binary content as HTML.
func crawlable(rec Record) bool {
	for _, c := range rec.Classifications {
		switch c.Category {
		case "JAVASCRIPT", "STATIC_ASSET", "DOWNLOAD":
			return false
		}
	}
	return true
}

// markScriptRef annotates a URL record as a script reference. It returns false, leaving the record
// untouched, when the URL already carries a strong non-script classification, so an image or font
// misleadingly referenced from a <script> tag is never relabelled as JavaScript.
func markScriptRef(rec *Record, parentURL string) bool {
	for _, c := range rec.Classifications {
		switch c.Category {
		case "JAVASCRIPT":
			rec.ScriptRef = true
			rec.ParentURL = parentURL
			return true
		case "STATIC_ASSET", "DOWNLOAD":
			return false
		}
	}
	kept := make([]UrlClassification, 0, len(rec.Classifications)+1)
	for _, c := range rec.Classifications {
		if c.Category == "HTML_PAGE" || c.Category == "UNKNOWN" {
			continue
		}
		kept = append(kept, c)
	}
	kept = append(kept, UrlClassification{Category: "JAVASCRIPT", Confidence: 0.6, EvidenceType: "SCRIPT_REF", Evidence: "referenced by <script src> in " + parentURL})
	rec.Classifications = kept
	rec.ScriptRef = true
	rec.ParentURL = parentURL
	return true
}

// mergeScriptRefClassifications merges a script-reference classification into an existing set,
// dropping HTML_PAGE/UNKNOWN fallbacks that the reference supersedes.
func mergeScriptRefClassifications(existing, incoming []UrlClassification) []UrlClassification {
	seen := map[string]bool{}
	out := make([]UrlClassification, 0, len(existing)+len(incoming))
	for _, list := range [][]UrlClassification{existing, incoming} {
		for _, c := range list {
			if c.Category == "HTML_PAGE" || c.Category == "UNKNOWN" {
				continue
			}
			if seen[c.Category] {
				continue
			}
			seen[c.Category] = true
			out = append(out, c)
		}
	}
	return out
}
