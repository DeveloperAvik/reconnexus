import { describe, expect, it } from "vitest";
import {
  color,
  formatCount,
  formatDuration,
  padVisible,
  setColorEnabled,
  statusLabel,
  statusSymbol,
  table,
  visibleWidth,
} from "../../apps/cli/src/output.js";

describe("CLI output helpers", () => {
  it("formats durations at every magnitude", () => {
    expect(formatDuration(0)).toBe("0ms");
    expect(formatDuration(6)).toBe("6ms");
    expect(formatDuration(999)).toBe("999ms");
    expect(formatDuration(1000)).toBe("1.0s");
    expect(formatDuration(6400)).toBe("6.4s");
    expect(formatDuration(9949)).toBe("9.9s");
    expect(formatDuration(10_000)).toBe("10s");
    expect(formatDuration(59_000)).toBe("59s");
    expect(formatDuration(94_400)).toBe("1m 34s");
    expect(formatDuration(632_000)).toBe("10m 32s");
    // A clock that went backwards must not render as a negative column.
    expect(formatDuration(-1)).toBe("");
    expect(formatDuration(Number.NaN)).toBe("");
  });

  it("groups record counts", () => {
    expect(formatCount(0)).toBe("0");
    expect(formatCount(894)).toBe("894");
    expect(formatCount(8290)).toBe("8,290");
  });

  it("measures and pads by visible width, ignoring colour escapes", () => {
    setColorEnabled(true);
    try {
      const painted = color.green("ok");
      expect(painted).not.toBe("ok");
      expect(visibleWidth(painted)).toBe(2);
      // The padded cell occupies 5 visible columns even though the string is longer.
      expect(visibleWidth(padVisible(painted, 5))).toBe(5);
      expect(padVisible(painted, 5, "right").startsWith("   ")).toBe(true);
    } finally {
      setColorEnabled(false);
    }
  });

  it("aligns columns and leaves the last one ragged", () => {
    const rows = table(
      [
        ["✓", "02", "subdomain discovery", "subfinder"],
        ["~", "03", "dns infra", "builtin-dns"],
      ],
      ["left", "left", "left", "left"],
    );
    const [a, b] = rows;
    expect(a).toBe("✓  02  subdomain discovery  subfinder");
    expect(b).toBe("~  03  dns infra            builtin-dns");
    // No trailing whitespace: a ragged final column keeps copied output clean.
    expect(rows.every((r) => r === r.trimEnd())).toBe(true);
  });

  it("right-aligns the columns asked for", () => {
    expect(table([["observations", "8,290"], ["relationships", "5,142"]], ["left", "right"])).toEqual([
      "observations   8,290",
      "relationships  5,142",
    ]);
  });

  it("maps every status this CLI can show to a distinct symbol and a readable label", () => {
    setColorEnabled(false);
    const statuses = ["SUCCEEDED", "PARTIAL", "SKIPPED", "FAILED", "BLOCKED", "CANCELLED", "RUNNING", "QUEUED", "SOURCE_UNAVAILABLE"];
    for (const s of statuses) {
      expect(statusSymbol(s).trim(), `symbol for ${s}`).not.toBe("");
      expect(statusLabel(s), `label for ${s}`).toBe(s.toLowerCase().replace(/_/g, " "));
    }
    expect(statusSymbol("SUCCEEDED")).not.toBe(statusSymbol("FAILED"));
    expect(statusSymbol("PARTIAL")).not.toBe(statusSymbol("SKIPPED"));
    // An unknown status still occupies the column so rows stay aligned.
    expect(statusSymbol("WHATEVER")).toBe(" ");
  });
});
