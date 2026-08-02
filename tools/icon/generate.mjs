/**
 * Satoshi Vault icon generator.
 *
 * Draws the brand mark — a vault door (orange ring with bolt holes) around the
 * Bitcoin ₿ — and writes every Android launcher icon, adaptive foreground,
 * splash screen and web favicon for both apps.
 *
 * No dependencies and no font: the ₿ is constructed from rectangles and circles
 * so the mark renders identically everywhere, offline, forever. Run with
 *   node tools/icon/generate.mjs
 * from the repository root.
 */

import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

// ---------------------------------------------------------------- PNG output

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, crc]);
}

function encodePng(width, height, rgba) {
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none
    Buffer.from(rgba.buffer, rgba.byteOffset + y * stride, stride).copy(raw, y * (stride + 1) + 1);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

// ------------------------------------------------------------------- palette

const INK = [0x0d, 0x0b, 0x08, 255];
const ORANGE = [0xf7, 0x93, 0x1a, 255];
const PAPER = [0xff, 0xfd, 0xf8, 255];
const CLEAR = [0, 0, 0, 0];

// ------------------------------------------------------------- the ₿ outline
// Glyph space is 1000 units tall with y pointing down. Bounding box of the
// finished mark is x 250..760, y 90..910 (see GLYPH_BOX below).

const GLYPH_BOX = { x0: 250, y0: 90, x1: 760, y1: 910 };

const inRect = (x, y, x0, y0, x1, y1) => x >= x0 && x < x1 && y >= y0 && y < y1;
const inCircle = (x, y, cx, cy, r) => (x - cx) ** 2 + (y - cy) ** 2 <= r * r;

function inGlyph(x, y) {
  // Two "D" bowls: a stroke rectangle whose right edge is closed by a half
  // disc, minus the counter (the enclosed white space) built the same way.
  const stem = inRect(x, y, 250, 180, 400, 820);
  const topOuter = inRect(x, y, 250, 180, 560, 520) || (x >= 560 && inCircle(x, y, 560, 350, 170));
  const topCounter = inRect(x, y, 400, 245, 560, 455) || (x >= 560 && inCircle(x, y, 560, 350, 105));
  const botOuter = inRect(x, y, 250, 480, 590, 820) || (x >= 590 && inCircle(x, y, 590, 650, 170));
  const botCounter = inRect(x, y, 400, 545, 590, 755) || (x >= 590 && inCircle(x, y, 590, 650, 105));
  const body = (stem || topOuter || botOuter) && !(topCounter || botCounter);
  // The two vertical strokes above and below the letter.
  const ticks =
    inRect(x, y, 320, 90, 400, 180) ||
    inRect(x, y, 470, 90, 550, 180) ||
    inRect(x, y, 320, 820, 400, 910) ||
    inRect(x, y, 470, 820, 550, 910);
  return body || ticks;
}

// ---------------------------------------------------------------- the mark

const BOLTS = 8;

/**
 * @param opts.shape     "rounded" | "circle" | "none"  — the icon backdrop
 * @param opts.variant   "signer" (hollow vault door) | "wallet" (solid coin)
 * @param opts.markR     mark radius as a fraction of the reference size
 * @param opts.glyphH    ₿ height as a fraction of the reference size
 */
function makeColorAt(width, height, opts) {
  const ref = Math.min(width, height);
  const cx = width / 2;
  const cy = height / 2;
  const markR = opts.markR * ref;
  const innerR = markR * 0.82;
  const boltR = markR * 0.055;
  const boltDist = (markR + innerR) / 2;
  const corner = 0.22 * ref;

  const glyphH = opts.glyphH * ref;
  const scale = glyphH / (GLYPH_BOX.y1 - GLYPH_BOX.y0);
  const gcx = (GLYPH_BOX.x0 + GLYPH_BOX.x1) / 2;
  const gcy = (GLYPH_BOX.y0 + GLYPH_BOX.y1) / 2;
  const glyphColor = opts.variant === "wallet" ? INK : PAPER;

  const bolts = [];
  for (let i = 0; i < BOLTS; i++) {
    const a = (Math.PI * 2 * i) / BOLTS + Math.PI / BOLTS;
    bolts.push([cx + Math.cos(a) * boltDist, cy + Math.sin(a) * boltDist]);
  }

  function inBackdrop(x, y) {
    if (opts.shape === "none") return false;
    if (opts.shape === "full") return true;
    if (opts.shape === "circle") return inCircle(x, y, cx, cy, ref / 2);
    // Rounded square.
    const qx = Math.max(corner - x, 0, x - (width - corner));
    const qy = Math.max(corner - y, 0, y - (height - corner));
    if (qx > 0 && qy > 0) return qx * qx + qy * qy <= corner * corner;
    return true;
  }

  return (x, y) => {
    let color = inBackdrop(x, y) ? INK : CLEAR;
    const dist2 = (x - cx) ** 2 + (y - cy) ** 2;
    const onMark =
      opts.variant === "wallet"
        ? dist2 <= markR * markR
        : dist2 <= markR * markR && dist2 >= innerR * innerR;
    if (onMark) {
      color = ORANGE;
      for (const [bx, by] of bolts) {
        if (inCircle(x, y, bx, by, boltR)) {
          color = INK;
          break;
        }
      }
    }
    const gx = (x - cx) / scale + gcx;
    const gy = (y - cy) / scale + gcy;
    if (inGlyph(gx, gy)) color = glyphColor;
    return color;
  };
}

/** 4x4 supersampled render — the only anti-aliasing this needs. */
function render(width, height, opts) {
  const colorAt = makeColorAt(width, height, opts);
  const out = new Uint8Array(width * height * 4);
  const S = 4;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      for (let sy = 0; sy < S; sy++) {
        for (let sx = 0; sx < S; sx++) {
          const c = colorAt(x + (sx + 0.5) / S, y + (sy + 0.5) / S);
          // Premultiply so transparent samples do not darken the edge.
          const alpha = c[3] / 255;
          r += c[0] * alpha;
          g += c[1] * alpha;
          b += c[2] * alpha;
          a += c[3];
        }
      }
      const n = S * S;
      const alphaAvg = a / n;
      const i = (y * width + x) * 4;
      if (alphaAvg > 0) {
        // Un-premultiply back to straight alpha.
        const k = 255 / alphaAvg;
        out[i] = Math.round(Math.min(255, (r / n) * k));
        out[i + 1] = Math.round(Math.min(255, (g / n) * k));
        out[i + 2] = Math.round(Math.min(255, (b / n) * k));
      }
      out[i + 3] = Math.round(alphaAvg);
    }
  }
  return encodePng(width, height, out);
}

// ------------------------------------------------------------------ targets

const DENSITIES = [
  ["mdpi", 48, 108],
  ["hdpi", 72, 162],
  ["xhdpi", 96, 216],
  ["xxhdpi", 144, 324],
  ["xxxhdpi", 192, 432],
];

// Portrait sizes; the landscape set is the same list with width/height swapped.
const SPLASHES = [
  ["mdpi", 320, 480],
  ["hdpi", 480, 800],
  ["xhdpi", 720, 1280],
  ["xxhdpi", 960, 1600],
  ["xxxhdpi", 1280, 1920],
];

// Full-bleed launcher icon and adaptive foreground (the latter must stay inside
// the 66/108 safe zone, hence the smaller mark).
const LEGACY = { markR: 0.4, glyphH: 0.52 };
const ADAPTIVE = { markR: 0.29, glyphH: 0.375, shape: "none" };

function write(path, buf) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, buf);
  console.log(`  ${path} (${buf.length.toLocaleString()} bytes)`);
}

function generateApp(appDir, variant) {
  const res = join(appDir, "android/app/src/main/res");
  console.log(`\n${variant}:`);

  for (const [density, legacy, adaptive] of DENSITIES) {
    const mip = join(res, `mipmap-${density}`);
    write(join(mip, "ic_launcher.png"), render(legacy, legacy, { ...LEGACY, shape: "rounded", variant }));
    write(join(mip, "ic_launcher_round.png"), render(legacy, legacy, { ...LEGACY, shape: "circle", variant }));
    write(join(mip, "ic_launcher_foreground.png"), render(adaptive, adaptive, { ...ADAPTIVE, variant }));
  }

  // The splash fills the whole screen, so it carries the ink field itself.
  const splashOpts = { markR: 0.15, glyphH: 0.195, shape: "full", variant };
  for (const [density, w, h] of SPLASHES) {
    const port = render(w, h, splashOpts);
    const land = render(h, w, splashOpts);
    write(join(res, `drawable-port-${density}`, "splash.png"), port);
    write(join(res, `drawable-land-${density}`, "splash.png"), land);
    if (density === "mdpi") write(join(res, "drawable", "splash.png"), land);
  }

  // The adaptive background layer is a flat colour behind the foreground.
  write(
    join(res, "values", "ic_launcher_background.xml"),
    Buffer.from(
      `<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <color name="ic_launcher_background">#0D0B08</color>\n</resources>\n`,
      "utf8",
    ),
  );

  // Browser tab icon for `vite dev` and any desktop use of the same bundle.
  write(join(appDir, "public", "favicon.png"), render(64, 64, { ...LEGACY, shape: "rounded", variant }));
}

const root = process.cwd();
generateApp(join(root, "apps/signer"), "signer");
generateApp(join(root, "apps/wallet"), "wallet");
// A large master copy for the README and store listings.
write(join(root, "docs/icon-signer.png"), render(512, 512, { ...LEGACY, shape: "rounded", variant: "signer" }));
write(join(root, "docs/icon-wallet.png"), render(512, 512, { ...LEGACY, shape: "rounded", variant: "wallet" }));
console.log("\ndone");
