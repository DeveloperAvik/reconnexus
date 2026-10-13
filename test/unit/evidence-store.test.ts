import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ArtifactTooLargeError, InvalidStorageUriError, LocalArtifactStore, sha256Hex } from "@reconnexus/evidence-contracts";

let dir: string;
let store: LocalArtifactStore;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "reconnexus-evidence-"));
  store = new LocalArtifactStore(dir);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("LocalArtifactStore", () => {
  it("stores content content-addressed and reads it back", async () => {
    const content = Buffer.from("hello evidence");
    const stored = await store.put(content);
    expect(stored.sha256).toBe(sha256Hex(content));
    expect(stored.storageUri).toBe(`sha256:${stored.sha256}`);
    expect(await store.exists(stored.storageUri)).toBe(true);
    expect((await store.get(stored.storageUri)).toString()).toBe("hello evidence");
  });

  it("is idempotent for identical content", async () => {
    const a = await store.put(Buffer.from("same"));
    const b = await store.put(Buffer.from("same"));
    expect(a.storageUri).toBe(b.storageUri);
  });

  it("enforces the size limit", async () => {
    await expect(store.put(Buffer.alloc(1000), { maxBytes: 10 })).rejects.toBeInstanceOf(ArtifactTooLargeError);
  });

  it("rejects path traversal in storage URIs", () => {
    expect(() => store.pathFor("sha256:../../etc/passwd")).toThrow(InvalidStorageUriError);
    expect(() => store.pathFor("file:///etc/passwd")).toThrow(InvalidStorageUriError);
  });
});
