/**
 * QR display (static + animated) and camera scanning.
 *
 * Dependencies (justified in docs/DEPENDENCIES.md):
 * - `qrcode`: pure-JS QR encoder, no network access, deterministic output.
 * - `jsqr`: pure-JS QR decoder operating on raw pixel data. The camera never
 *   leaves the device; frames are processed locally and discarded.
 */

import QRCode from "qrcode";
import jsQR from "jsqr";

export async function renderQr(canvas: HTMLCanvasElement, text: string, size = 320): Promise<void> {
  await QRCode.toCanvas(canvas, text, {
    width: size,
    margin: 1,
    errorCorrectionLevel: "M",
    color: { dark: "#0d0b08", light: "#fffdf8" },
  });
}

/** Cycles a list of frames on one canvas — the animated-QR sender. */
export class AnimatedQr {
  private timer: ReturnType<typeof setInterval> | undefined;
  private index = 0;

  constructor(
    private readonly canvas: HTMLCanvasElement,
    private readonly frames: string[],
    private readonly intervalMs = 350,
    private readonly size = 320,
  ) {
    if (frames.length === 0) throw new Error("no frames to display");
  }

  start(onFrame?: (index: number, total: number) => void): void {
    const draw = () => {
      void renderQr(this.canvas, this.frames[this.index]!, this.size);
      onFrame?.(this.index, this.frames.length);
      this.index = (this.index + 1) % this.frames.length;
    };
    draw();
    if (this.frames.length > 1) {
      this.timer = setInterval(draw, this.intervalMs);
    }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }
}

export interface ScannerHandle {
  stop: () => void;
  video: HTMLVideoElement;
}

/**
 * Starts the camera and calls `onResult` for every decoded QR string.
 * Returns a handle that MUST be stopped when the view is left (releases the
 * camera). Frames are decoded in-memory and never persisted.
 */
export async function startScanner(
  container: HTMLElement,
  onResult: (text: string) => void,
): Promise<ScannerHandle> {
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } },
    audio: false,
  });
  const video = document.createElement("video");
  video.className = "scanner";
  video.setAttribute("playsinline", "");
  video.muted = true;
  video.srcObject = stream;
  container.append(video);
  await video.play();

  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  let running = true;
  let lastText = "";
  let lastAt = 0;

  const tick = () => {
    if (!running) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA && ctx) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0);
      const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(image.data, image.width, image.height, { inversionAttempts: "dontInvert" });
      if (code && code.data) {
        const now = Date.now();
        // Debounce identical reads of a static code, but let animated
        // sequences flow through freely.
        if (code.data !== lastText || now - lastAt > 400) {
          lastText = code.data;
          lastAt = now;
          onResult(code.data);
        }
      }
    }
    if (running) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);

  return {
    video,
    stop: () => {
      running = false;
      for (const track of stream.getTracks()) track.stop();
      video.remove();
    },
  };
}
