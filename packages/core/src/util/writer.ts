/**
 * Binary writer/reader for Bitcoin wire serialization.
 * Little-endian integers and CompactSize varints per the Bitcoin P2P format.
 * The reader validates every length before touching the buffer: all inputs
 * (PSBTs, QR payloads, network data) are treated as hostile.
 */

export class ByteWriter {
  private chunks: Uint8Array[] = [];

  bytes(b: Uint8Array): this {
    this.chunks.push(b);
    return this;
  }

  u8(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 0xff) throw new Error("u8 out of range");
    return this.bytes(new Uint8Array([n]));
  }

  u16le(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new Error("u16 out of range");
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, n, true);
    return this.bytes(b);
  }

  u32le(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error("u32 out of range");
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, true);
    return this.bytes(b);
  }

  i32le(n: number): this {
    if (!Number.isInteger(n) || n < -0x80000000 || n > 0x7fffffff) throw new Error("i32 out of range");
    const b = new Uint8Array(4);
    new DataView(b.buffer).setInt32(0, n, true);
    return this.bytes(b);
  }

  u64le(n: bigint): this {
    if (n < 0n || n > 0xffffffffffffffffn) throw new Error("u64 out of range");
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, n, true);
    return this.bytes(b);
  }

  /** Bitcoin CompactSize. */
  varInt(n: number | bigint): this {
    const v = BigInt(n);
    if (v < 0n) throw new Error("varint negative");
    if (v < 0xfdn) return this.u8(Number(v));
    if (v <= 0xffffn) return this.u8(0xfd).u16le(Number(v));
    if (v <= 0xffffffffn) return this.u8(0xfe).u32le(Number(v));
    return this.u8(0xff).u64le(v);
  }

  /** CompactSize length prefix followed by the bytes. */
  varBytes(b: Uint8Array): this {
    return this.varInt(b.length).bytes(b);
  }

  finish(): Uint8Array {
    let total = 0;
    for (const c of this.chunks) total += c.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of this.chunks) {
      out.set(c, offset);
      offset += c.length;
    }
    return out;
  }
}

export class ByteReader {
  private offset = 0;
  constructor(private readonly buf: Uint8Array) {}

  get remaining(): number {
    return this.buf.length - this.offset;
  }

  get position(): number {
    return this.offset;
  }

  isDone(): boolean {
    return this.offset === this.buf.length;
  }

  bytes(n: number): Uint8Array {
    if (!Number.isInteger(n) || n < 0) throw new Error("invalid read length");
    if (this.remaining < n) throw new Error("unexpected end of data");
    const out = this.buf.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  u8(): number {
    return this.bytes(1)[0]!;
  }

  u16le(): number {
    const b = this.bytes(2);
    return new DataView(b.buffer, b.byteOffset, 2).getUint16(0, true);
  }

  u32le(): number {
    const b = this.bytes(4);
    return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true);
  }

  i32le(): number {
    const b = this.bytes(4);
    return new DataView(b.buffer, b.byteOffset, 4).getInt32(0, true);
  }

  u64le(): bigint {
    const b = this.bytes(8);
    return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, true);
  }

  varInt(): bigint {
    const first = this.u8();
    if (first < 0xfd) return BigInt(first);
    if (first === 0xfd) {
      const v = this.u16le();
      if (v < 0xfd) throw new Error("non-canonical varint");
      return BigInt(v);
    }
    if (first === 0xfe) {
      const v = this.u32le();
      if (v <= 0xffff) throw new Error("non-canonical varint");
      return BigInt(v);
    }
    const v = this.u64le();
    if (v <= 0xffffffffn) throw new Error("non-canonical varint");
    return v;
  }

  /** varint length capped to remaining bytes, then that many bytes. */
  varBytes(): Uint8Array {
    const len = this.varInt();
    if (len > BigInt(this.remaining)) throw new Error("declared length exceeds data");
    return this.bytes(Number(len));
  }
}
