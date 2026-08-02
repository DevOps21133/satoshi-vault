/**
 * Multi-source entropy pool for seed generation.
 *
 * Architecture: a running SHA-256 chain absorbs samples from physical sensors (camera
 * frames, microphone buffers, touch/pointer events, accelerometer) and the
 * platform CSPRNG. The pool is bookended: a large CSPRNG block is absorbed at
 * initialization AND at extraction, so the final seed is AT LEAST as strong
 * as the OS CSPRNG alone even if every sensor source is broken or hostile.
 * Sensor entropy can only add security, never reduce it.
 *
 * Design properties:
 * - Domain separation: every absorbed sample is framed with a source tag and
 *   length, so sources cannot impersonate each other and concatenation
 *   ambiguity is impossible.
 * - Continuous health tests per NIST SP 800-90B on each sensor source
 *   (Repetition Count Test + Adaptive Proportion Test). A failing source
 *   stops earning entropy credit — its data is still absorbed (mixing bad
 *   data into a hash chain is harmless) but it can no longer satisfy the
 *   collection target.
 * - Conservative credit accounting: sensor bytes are credited at 1 bit of
 *   min-entropy per 8 bytes (1/64 of their size in bits), capped at 64 bits
 *   per sample so no single frame can satisfy the target, tallied per source,
 *   and revoked retroactively if a source later fails its health tests. The
 *   target demands 2x the requested seed strength from sensors on top of the
 *   CSPRNG bookends.
 */

import { sha256 } from "@noble/hashes/sha2";
import { concatBytes, zeroize } from "../util/bytes.js";

export type EntropySource = "camera" | "microphone" | "touch" | "accelerometer" | "csprng";

const DOMAIN_PREFIX = "SatoshiVault/entropy/v1/";

function domainTag(source: EntropySource): Uint8Array {
  return new TextEncoder().encode(DOMAIN_PREFIX + source);
}

function csprngBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/**
 * NIST SP 800-90B 4.4 continuous health tests over a byte stream, assuming a
 * conservative 1 bit of min-entropy per byte sample.
 */
class SourceHealth {
  /** RCT: 1 + ceil(20 / H) with H = 1 bit/sample. */
  private static readonly RCT_CUTOFF = 21;
  /** APT: window 512, cutoff for H = 1 bit (SP 800-90B table). */
  private static readonly APT_WINDOW = 512;
  private static readonly APT_CUTOFF = 410;

  private lastByte = -1;
  private repeatCount = 0;
  private aptReference = -1;
  private aptCount = 0;
  private aptSeen = 0;
  failed = false;

  absorb(data: Uint8Array): void {
    if (this.failed) return;
    for (const byte of data) {
      // Repetition Count Test
      if (byte === this.lastByte) {
        this.repeatCount++;
        if (this.repeatCount >= SourceHealth.RCT_CUTOFF) {
          this.failed = true;
          return;
        }
      } else {
        this.lastByte = byte;
        this.repeatCount = 1;
      }
      // Adaptive Proportion Test
      if (this.aptSeen === 0) {
        this.aptReference = byte;
        this.aptCount = 1;
        this.aptSeen = 1;
      } else {
        if (byte === this.aptReference) this.aptCount++;
        this.aptSeen++;
        if (this.aptCount >= SourceHealth.APT_CUTOFF) {
          this.failed = true;
          return;
        }
        if (this.aptSeen >= SourceHealth.APT_WINDOW) {
          this.aptSeen = 0;
        }
      }
    }
  }
}

export interface EntropyProgress {
  /** 0..1 progress toward the sensor collection target. */
  ratio: number;
  creditedBits: number;
  targetBits: number;
  /** Sources currently marked unhealthy by the 800-90B tests. */
  failedSources: EntropySource[];
  /**
   * Per-source credit for every sensor source that has delivered at least one
   * sample. A failed source reports bits: 0 (its credit is revoked).
   */
  bySource: { source: EntropySource; bits: number; failed: boolean }[];
}

export class EntropyPool {
  private state: Uint8Array;
  private health = new Map<EntropySource, SourceHealth>();
  /**
   * Credit is tallied per source and summed only over currently-healthy
   * sources, so a source that fails a health test AFTER earning credit is
   * retroactively revoked — its earlier samples are no longer trusted.
   */
  private creditBySource = new Map<EntropySource, number>();
  private readonly targetBits: number;
  private extracted = false;

  /** @param seedStrengthBits requested seed entropy (128..256). */
  constructor(seedStrengthBits: number) {
    if (![128, 160, 192, 224, 256].includes(seedStrengthBits)) {
      throw new Error("seed strength must be 128/160/192/224/256 bits");
    }
    // Demand 2x the seed strength from sensors, on top of the CSPRNG bookends.
    this.targetBits = seedStrengthBits * 2;
    // Bookend #1: absorb a large CSPRNG block at init.
    this.state = sha256(concatBytes(domainTag("csprng"), csprngBytes(1024)));
  }

  /** Absorb a sensor sample. Data is zeroized after absorption. */
  addSample(source: EntropySource, data: Uint8Array): void {
    if (this.extracted) throw new Error("pool already extracted");
    if (data.length === 0) return;
    if (source !== "csprng") {
      let monitor = this.health.get(source);
      if (!monitor) {
        monitor = new SourceHealth();
        this.health.set(source, monitor);
      }
      monitor.absorb(data);
      if (!monitor.failed) {
        // Conservative credit: 1 bit per 8 bytes, capped at 64 bits per
        // sample. The low cap forces MANY samples over time (a single large
        // camera frame must not satisfy the target on its own), giving the
        // health tests a real data series to judge.
        const prev = this.creditBySource.get(source) ?? 0;
        this.creditBySource.set(source, prev + Math.min(Math.floor(data.length / 8), 64));
      }
    }
    const lenTag = new TextEncoder().encode(`/${data.length}/`);
    const next = sha256(concatBytes(this.state, domainTag(source), lenTag, data));
    zeroize(this.state, data);
    this.state = next;
  }

  /** Sum of credit from sources that are healthy RIGHT NOW. */
  private creditedBits(): number {
    let total = 0;
    for (const [source, bits] of this.creditBySource) {
      if (!this.health.get(source)?.failed) total += bits;
    }
    return total;
  }

  progress(): EntropyProgress {
    const failedSources = [...this.health.entries()].filter(([, h]) => h.failed).map(([s]) => s);
    const credited = this.creditedBits();
    // Union of both maps: a source that fails health tests on its very first
    // sample never earns credit but must still be listed (bits 0, failed).
    const seen = new Set<EntropySource>([...this.creditBySource.keys(), ...this.health.keys()]);
    const bySource = [...seen].map((source) => {
      const failed = this.health.get(source)?.failed ?? false;
      return { source, bits: failed ? 0 : this.creditBySource.get(source) ?? 0, failed };
    });
    return {
      ratio: Math.min(1, credited / this.targetBits),
      creditedBits: credited,
      targetBits: this.targetBits,
      failedSources,
      bySource,
    };
  }

  /**
   * Extract seed entropy. Requires the sensor target to be met.
   * Bookend #2: a fresh CSPRNG block is mixed in at extraction, so the output
   * is never weaker than the platform CSPRNG.
   */
  extract(bytes: 16 | 20 | 24 | 28 | 32): Uint8Array {
    if (this.extracted) throw new Error("pool already extracted");
    if (this.creditedBits() < this.targetBits) {
      throw new Error("not enough sensor entropy collected");
    }
    const final = sha256(
      concatBytes(this.state, domainTag("csprng"), csprngBytes(1024), new TextEncoder().encode("/extract")),
    );
    this.extracted = true;
    zeroize(this.state);
    const out = final.slice(0, bytes);
    if (out.length !== bytes) throw new Error("extraction failed");
    zeroize(final);
    return out;
  }

  /** Zeroize and discard the pool without extracting. */
  destroy(): void {
    zeroize(this.state);
    this.extracted = true;
  }
}
