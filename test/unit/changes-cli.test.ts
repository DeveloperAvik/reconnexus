import { describe, expect, it } from "vitest";
import type { ScanComparison, CategoryComparison, ChangeItem } from "@reconnexus/control-plane";
import { renderChangesHtml, renderChangesHuman } from "../../apps/cli/src/commands/changes.js";

const hostile = `</title><script>alert('xss')</script><img src=x onerror="alert(1)">`;

function item(partial: Partial<ChangeItem>): ChangeItem {
  return {
    category: "http",
    outcome: "ADDED",
    key: "k",
    assetType: "SERVICE",
    assetValue: "https://app.example.com",
    stage: "04-http-probe",
    baseline: null,
    current: { source: "http", observedAt: "2026-02-01T00:00:00.000Z", fields: {} },
    ...partial,
  };
}

function comparison(cat: Partial<CategoryComparison>): ScanComparison {
  const totals = { ADDED: 0, REMOVED: 0, CHANGED: 0, UNCHANGED: 0, UNKNOWN: 0, ...(cat.totals ?? {}) };
  return {
    baselineScanId: "11111111-1111-1111-1111-111111111111",
    currentScanId: "22222222-2222-2222-2222-222222222222",
    projectId: "p",
    rootDomain: "example.com",
    generatedAt: "2026-02-01T00:00:00.000Z",
    categories: [{ category: "http", description: "HTTP services", coverage: [], totals, total: cat.changes?.length ?? 0, changes: cat.changes ?? [], truncated: false }],
    limitations: [],
  };
}

describe("changes command rendering", () => {
  it("HTML-escapes every interpolated value, including hostile asset names and reasons", () => {
    const cmp = comparison({
      totals: { ADDED: 1, UNKNOWN: 1 },
      changes: [
        item({ outcome: "CHANGED", assetValue: hostile, changedFields: ["title"], baseline: { source: "s", observedAt: "t", fields: { title: hostile } }, current: { source: "s", observedAt: "t", fields: { title: hostile } } }),
        item({ outcome: "UNKNOWN", assetValue: hostile, reason: hostile }),
      ],
    });
    const html = renderChangesHtml(cmp);
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<img/i);
    // No real tag carries an event handler (the hostile text survives only as escaped data).
    for (const tag of html.matchAll(/<[a-z][^>]*>/gi)) {
      expect(tag[0]).not.toMatch(/\son[a-z]+\s*=/i);
    }
    expect(html).toContain("&lt;script&gt;");
    // Only in-document structure; no real element loads an external resource.
    expect(html).not.toMatch(/<link\b/i);
    for (const tag of html.matchAll(/<[a-z][^>]*>/gi)) {
      expect(tag[0]).not.toMatch(/\s(src|href)\s*=/i);
      expect(tag[0]).not.toMatch(/url\(\s*https?:/i);
    }
  });

  it("human output shows per-category counts and skips UNCHANGED rows", () => {
    const cmp = comparison({
      totals: { ADDED: 1, UNCHANGED: 5 },
      changes: [
        item({ outcome: "ADDED", assetValue: "https://new.example.com" }),
        item({ outcome: "UNCHANGED", assetValue: "https://same.example.com" }),
      ],
    });
    const text = renderChangesHuman(cmp);
    expect(text).toContain("Change intelligence");
    expect(text).toContain("+1");
    expect(text).toContain("new.example.com");
    expect(text).not.toContain("same.example.com");
  });
});
