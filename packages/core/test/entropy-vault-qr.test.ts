import { describe, it, expect } from "vitest";
import { EntropyPool } from "../src/entropy/entropy.js";
import { encryptVault, decryptVault, KdfParams } from "../src/vault/vault.js";
import { encodeChunks, parseFrame, ChunkAssembler } from "../src/qr/chunks.js";
import { entropyToMnemonic, validateMnemonic } from "../src/bip39/mnemonic.js";
import { bytesToHex } from "../src/util/bytes.js";
import { sha256 } from "@noble/hashes/sha2";

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

// Fast-but-in-bounds KDF params so tests stay quick (8 MiB, t=1).
const TEST_KDF: KdfParams = { timeCost: 1, memoryLog2KiB: 13, parallelism: 1 };

describe("entropy pool", () => {
  it("collects sensor entropy and produces valid BIP39 material", () => {
    const pool = new EntropyPool(256);
    while (pool.progress().ratio < 1) {
      pool.addSample("camera", randomBytes(1024));
      pool.addSample("microphone", randomBytes(1024));
      pool.addSample("touch", randomBytes(64));
    }
    const entropy = pool.extract(32);
    expect(entropy.length).toBe(32);
    const words = entropyToMnemonic(entropy);
    expect(words.length).toBe(24);
    expect(validateMnemonic(words).ok).toBe(true);
  });

  it("256-bit extraction yields a valid 24-word mnemonic", () => {
    const pool = new EntropyPool(256);
    while (pool.progress().ratio < 1) pool.addSample("camera", randomBytes(4096));
    const entropy = pool.extract(32);
    expect(entropy.length).toBe(32); // exactly 256 bits
    const words = entropyToMnemonic(entropy);
    expect(words.length).toBe(24);
    expect(validateMnemonic(words).ok).toBe(true);
  });

  it("sensor data alone never determines the seed (CSPRNG always mixed in)", () => {
    // Two pools fed byte-identical sensor input must still produce different
    // entropy: user actions can only ADD to the OS CSPRNG, never replace it.
    // This is what stops a predictable or hostile sensor from fixing the seed.
    // Deterministic across both runs (a hash keystream, not the OS CSPRNG) yet
    // structurally healthy, so the samples earn full credit and the pools are
    // genuinely fed byte-identical sensor data.
    const scripted = Array.from({ length: 32 }, (_, i) => {
      const b = new Uint8Array(4096);
      for (let block = 0; block * 32 < b.length; block++) {
        b.set(sha256(new Uint8Array([i, block & 0xff, block >> 8])), block * 32);
      }
      return b;
    });
    const run = () => {
      const pool = new EntropyPool(256);
      for (const sample of scripted) pool.addSample("camera", sample.slice());
      return bytesToHex(pool.extract(32));
    };
    expect(run()).not.toBe(run());
  });

  it("refuses extraction before the sensor target is met", () => {
    const pool = new EntropyPool(128);
    pool.addSample("camera", randomBytes(64));
    expect(() => pool.extract(16)).toThrow(/not enough/);
  });

  it("refuses double extraction", () => {
    const pool = new EntropyPool(128);
    while (pool.progress().ratio < 1) pool.addSample("camera", randomBytes(4096));
    pool.extract(16);
    expect(() => pool.extract(16)).toThrow(/already extracted/);
  });

  it("a single large sample cannot satisfy the target (per-sample credit cap)", () => {
    const pool = new EntropyPool(128);
    pool.addSample("camera", randomBytes(65_536));
    expect(pool.progress().creditedBits).toBeLessThanOrEqual(64);
    expect(() => pool.extract(16)).toThrow(/not enough/);
  });

  it("credit is revoked when a source fails its health tests later", () => {
    const pool = new EntropyPool(128);
    pool.addSample("camera", randomBytes(1024));
    const before = pool.progress().creditedBits;
    expect(before).toBeGreaterThan(0);
    pool.addSample("camera", new Uint8Array(64).fill(0x55)); // camera gets stuck
    const progress = pool.progress();
    expect(progress.failedSources).toContain("camera");
    expect(progress.creditedBits).toBe(0);
  });

  it("health test disqualifies a stuck source (repetition count test)", () => {
    const pool = new EntropyPool(128);
    pool.addSample("touch", new Uint8Array(64).fill(0xaa)); // stuck sensor
    const progress = pool.progress();
    expect(progress.failedSources).toContain("touch");
    expect(progress.creditedBits).toBe(0);
  });

  it("health test disqualifies a heavily biased source (adaptive proportion test)", () => {
    const pool = new EntropyPool(128);
    // 90% zeros with varied filler to dodge the repetition test
    const biased = new Uint8Array(2048);
    for (let i = 0; i < biased.length; i++) biased[i] = i % 10 === 0 ? 1 + (i % 250) : 0;
    pool.addSample("accelerometer", biased);
    expect(pool.progress().failedSources).toContain("accelerometer");
  });

  it("a periodic source earns no credit (structural screen beyond 800-90B)", () => {
    // Neither the repetition count test nor the adaptive proportion test sees
    // anything wrong with these: no value repeats 21 times in a row, and no
    // value dominates 80% of a window. They carry no entropy whatsoever.
    const alternating = new Uint8Array(4096);
    for (let i = 0; i < alternating.length; i++) alternating[i] = i % 2 === 0 ? 0x00 : 0xff;
    const sawtooth = new Uint8Array(4096);
    for (let i = 0; i < sawtooth.length; i++) sawtooth[i] = i & 0xff;

    for (const pattern of [alternating, sawtooth]) {
      const pool = new EntropyPool(256);
      for (let i = 0; i < 40; i++) pool.addSample("camera", pattern.slice());
      const progress = pool.progress();
      expect(progress.failedSources).toContain("camera");
      expect(progress.creditedBits).toBe(0);
      expect(() => pool.extract(32)).toThrow(/not enough/);
    }
  });

  it("real random samples are never rejected by the periodicity screen", () => {
    // The screen must not fire on genuine sensor data, including the short
    // 64-byte pointer batches the ceremony emits.
    for (const size of [64, 256, 4096]) {
      const pool = new EntropyPool(128);
      pool.addSample("touch", randomBytes(size));
      expect(pool.progress().failedSources).toEqual([]);
    }
  });

  it("progress reports per-source credit, zeroed for failed sources", () => {
    const pool = new EntropyPool(128);
    pool.addSample("camera", randomBytes(1024));
    pool.addSample("microphone", randomBytes(256));
    pool.addSample("touch", new Uint8Array(10_000).fill(1)); // fails health tests
    const by = new Map(pool.progress().bySource.map((s) => [s.source, s]));
    expect(by.get("camera")).toEqual({ source: "camera", bits: 64, failed: false });
    expect(by.get("microphone")).toEqual({ source: "microphone", bits: 32, failed: false });
    expect(by.get("touch")).toEqual({ source: "touch", bits: 0, failed: true });
    expect(by.has("accelerometer")).toBe(false); // never sampled → not listed
  });

  it("failed source cannot satisfy the target but healthy sources still can", () => {
    const pool = new EntropyPool(128);
    pool.addSample("touch", new Uint8Array(10_000).fill(1));
    expect(pool.progress().ratio).toBe(0);
    while (pool.progress().ratio < 1) pool.addSample("camera", randomBytes(4096));
    expect(pool.progress().failedSources).toContain("touch");
    expect(() => pool.extract(16)).not.toThrow();
  });
});

describe("vault encryption", () => {
  it("round-trips", async () => {
    const secret = new TextEncoder().encode("abandon ability able about above absent");
    const vault = await encryptVault(secret, "correct horse battery staple", TEST_KDF);
    const opened = await decryptVault(vault, "correct horse battery staple");
    expect(new TextDecoder().decode(opened)).toBe("abandon ability able about above absent");
  });

  it("wrong password fails with an opaque error", async () => {
    const vault = await encryptVault(randomBytes(32), "right", TEST_KDF);
    await expect(decryptVault(vault, "wrong")).rejects.toThrow(/unable to decrypt/);
  });

  it("any tampered byte fails authentication", async () => {
    const vault = await encryptVault(randomBytes(64), "pw", TEST_KDF);
    for (const offset of [1, 10, 25, vault.length - 1]) {
      const tampered = vault.slice();
      tampered[offset] = (tampered[offset] ?? 0) ^ 0x01;
      await expect(decryptVault(tampered, "pw")).rejects.toThrow();
    }
  });

  it("two encryptions of the same plaintext differ (fresh salt+IV)", async () => {
    const secret = randomBytes(32);
    const a = await encryptVault(secret, "pw", TEST_KDF);
    const b = await encryptVault(secret, "pw", TEST_KDF);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });

  it("rejects out-of-bounds KDF parameters on decrypt (downgrade defense)", async () => {
    const vault = await encryptVault(randomBytes(16), "pw", TEST_KDF);
    const downgraded = vault.slice();
    downgraded[2] = 1; // 2 KiB memory — below the accepted floor
    await expect(decryptVault(downgraded, "pw")).rejects.toThrow();
  });

  it("rejects empty password", async () => {
    await expect(encryptVault(randomBytes(16), "", TEST_KDF)).rejects.toThrow(/empty/);
  });
});

describe("QR chunk framing", () => {
  it("single-frame round trip", () => {
    const payload = randomBytes(100);
    const frames = encodeChunks("XPUB", payload);
    expect(frames.length).toBe(1);
    const asm = new ChunkAssembler();
    asm.add(frames[0]!);
    const result = asm.assemble();
    expect(result.type).toBe("XPUB");
    expect(bytesToHex(result.payload)).toBe(bytesToHex(payload));
  });

  it("multi-frame reassembly out of order with duplicates", () => {
    const payload = randomBytes(2500);
    const frames = encodeChunks("PSBT", payload, 300);
    expect(frames.length).toBe(9);
    const asm = new ChunkAssembler();
    const shuffled = [...frames].reverse();
    for (const f of shuffled) asm.add(f);
    asm.add(frames[3]!); // duplicate is fine
    expect(asm.isComplete()).toBe(true);
    expect(bytesToHex(asm.assemble().payload)).toBe(bytesToHex(payload));
  });

  it("frames from a different transfer are ignored", () => {
    const a = encodeChunks("PSBT", randomBytes(600), 300);
    const b = encodeChunks("PSBT", randomBytes(600), 300);
    const asm = new ChunkAssembler();
    asm.add(a[0]!);
    const progress = asm.add(b[0]!); // stale animation on screen
    expect(progress.received).toBe(1);
    asm.add(a[1]!);
    expect(asm.isComplete()).toBe(true);
  });

  it("rejects garbage and oversized frames", () => {
    expect(() => parseFrame("hello world")).toThrow();
    expect(() => parseFrame("SV1:EVIL:1/1:aabbccddaabbccdd:QUJD")).toThrow();
    expect(() => parseFrame("SV1:PSBT:2/1:aabbccddaabbccdd:QUJD")).toThrow(/index/);
    expect(() => parseFrame("SV1:PSBT:1/1:aabbccdd:QUJD")).toThrow(); // 32-bit groupId retired
    expect(() => parseFrame("x".repeat(5000))).toThrow(/too long/);
  });

  it("groupId commits to the frame type, not just the payload", () => {
    const payload = randomBytes(100);
    const asPsbt = parseFrame(encodeChunks("PSBT", payload)[0]!);
    const asTxn = parseFrame(encodeChunks("TXN", payload)[0]!);
    expect(asPsbt.groupId).not.toBe(asTxn.groupId);
    // Re-labelling a frame's type without recomputing the id must not assemble.
    const relabelled = encodeChunks("PSBT", payload)[0]!.replace(":PSBT:", ":TXN:");
    const asm = new ChunkAssembler();
    asm.add(relabelled);
    expect(() => asm.assemble()).toThrow(/hash mismatch/);
  });

  it("large payloads auto-scale the frame size to fit MAX_FRAMES", () => {
    const payload = new Uint8Array(900_000);
    for (let i = 0; i < payload.length; i++) payload[i] = i & 0xff;
    const frames = encodeChunks("PSBT", payload);
    expect(frames.length).toBeLessThanOrEqual(2000);
    const asm = new ChunkAssembler();
    for (const f of frames) asm.add(f);
    expect(asm.isComplete()).toBe(true);
    expect(bytesToHex(asm.assemble().payload)).toBe(bytesToHex(payload));
  });

  it("payload tampering is detected at assembly", () => {
    const payload = randomBytes(600);
    const frames = encodeChunks("TXN", payload, 300);
    // Forge frame 2 with different payload bytes but the same groupId.
    const parsed = parseFrame(frames[1]!);
    const forged = `SV1:TXN:2/2:${parsed.groupId}:QUJDREVGRw`;
    const asm = new ChunkAssembler();
    asm.add(frames[0]!);
    asm.add(forged);
    expect(asm.isComplete()).toBe(true);
    expect(() => asm.assemble()).toThrow(/hash mismatch/);
  });

  it("conflicting payloads for the same frame index throw", () => {
    const frames = encodeChunks("TXN", randomBytes(600), 300);
    const parsed = parseFrame(frames[0]!);
    const conflicting = `SV1:TXN:1/2:${parsed.groupId}:QUJDREVGRw`;
    const asm = new ChunkAssembler();
    asm.add(frames[0]!);
    expect(() => asm.add(conflicting)).toThrow(/conflicting/);
  });
});
