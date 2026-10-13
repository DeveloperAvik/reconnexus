import { createHash } from "node:crypto";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

export function sha256Hex(content: Buffer | string): string {
  return createHash("sha256").update(content).digest("hex");
}

export interface StoredArtifact {
  /** Content-addressed URI, e.g. `sha256:<hex>`. */
  storageUri: string;
  sha256: string;
  sizeBytes: number;
}

/**
 * Storage abstraction. Phase 1 ships a local filesystem implementation;
 * an object-storage backend can implement the same interface later.
 */
export interface ArtifactStore {
  put(content: Buffer, opts?: { maxBytes?: number }): Promise<StoredArtifact>;
  get(storageUri: string): Promise<Buffer>;
  exists(storageUri: string): Promise<boolean>;
  pathFor(storageUri: string): string;
}

export class ArtifactTooLargeError extends Error {
  constructor(size: number, limit: number) {
    super(`artifact of ${size} bytes exceeds limit of ${limit} bytes`);
    this.name = "ArtifactTooLargeError";
  }
}

export class InvalidStorageUriError extends Error {
  constructor(uri: string) {
    super(`invalid storage URI: ${uri}`);
    this.name = "InvalidStorageUriError";
  }
}

const SHA_PREFIX = "sha256:";
const SHA_RE = /^[0-9a-f]{64}$/;

/** Content-addressed local filesystem store. */
export class LocalArtifactStore implements ArtifactStore {
  constructor(private readonly root: string) {}

  pathFor(storageUri: string): string {
    if (!storageUri.startsWith(SHA_PREFIX)) throw new InvalidStorageUriError(storageUri);
    const hex = storageUri.slice(SHA_PREFIX.length);
    if (!SHA_RE.test(hex)) throw new InvalidStorageUriError(storageUri);
    return join(this.root, hex.slice(0, 2), hex);
  }

  async put(content: Buffer, opts: { maxBytes?: number } = {}): Promise<StoredArtifact> {
    const limit = opts.maxBytes ?? Number.POSITIVE_INFINITY;
    if (content.length > limit) throw new ArtifactTooLargeError(content.length, limit);
    const sha256 = sha256Hex(content);
    const storageUri = `${SHA_PREFIX}${sha256}`;
    const target = this.pathFor(storageUri);
    await mkdir(join(this.root, sha256.slice(0, 2)), { recursive: true });
    // Content-addressed writes are idempotent.
    if (!(await this.exists(storageUri))) {
      await writeFile(target, content, { mode: 0o600 });
    }
    return { storageUri, sha256, sizeBytes: content.length };
  }

  async get(storageUri: string): Promise<Buffer> {
    return readFile(this.pathFor(storageUri));
  }

  async exists(storageUri: string): Promise<boolean> {
    try {
      const s = await stat(this.pathFor(storageUri));
      return s.isFile();
    } catch {
      return false;
    }
  }
}
