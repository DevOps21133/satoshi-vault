/**
 * The entropy ceremony: wires physical sensors (camera, microphone, pointer,
 * accelerometer) into the core EntropyPool. All sensor data stays on-device
 * and is absorbed into the hash chain, then discarded.
 *
 * The pool's CSPRNG bookends guarantee the seed is never weaker than the OS
 * CSPRNG — the sensors add entropy on top and are health-checked (NIST
 * SP 800-90B) so a dead sensor cannot satisfy the collection target.
 */

import { EntropyPool, EntropyProgress } from "@satoshivault/core";

export interface CeremonyCallbacks {
  onProgress: (p: EntropyProgress) => void;
  /** 0..1 microphone activity for the level meter. */
  onMicLevel: (level: number) => void;
  onSensorError: (sensor: string, message: string) => void;
}

const CAMERA_SIDE = 64; // downsampled frame edge; RGB of 64x64 = 12288 bytes
const CAMERA_INTERVAL_MS = 350;
const MIC_INTERVAL_MS = 300;
const POINTER_BATCH = 64; // bytes buffered before absorbing a touch sample

export class Ceremony {
  readonly pool: EntropyPool;
  private cleanups: (() => void)[] = [];
  private stopped = false;

  constructor(seedStrengthBits: number) {
    this.pool = new EntropyPool(seedStrengthBits);
  }

  async start(videoContainer: HTMLElement, cb: CeremonyCallbacks): Promise<void> {
    this.startPointer(cb);
    this.startMotion(cb);
    // Camera and mic are independent: one being denied must not block the other.
    await Promise.all([this.startCamera(videoContainer, cb), this.startMicrophone(cb)]);
  }

  private absorb(source: "camera" | "microphone" | "touch" | "accelerometer", data: Uint8Array, cb: CeremonyCallbacks): void {
    if (this.stopped) return;
    this.pool.addSample(source, data);
    cb.onProgress(this.pool.progress());
  }

  /**
   * Register a resource release. If stop() already ran (it can race the
   * getUserMedia/play awaits), the release runs IMMEDIATELY — otherwise the
   * camera/microphone would stay live with no owner.
   */
  private addCleanup(fn: () => void): void {
    if (this.stopped) {
      fn();
      return;
    }
    this.cleanups.push(fn);
  }

  private async startCamera(container: HTMLElement, cb: CeremonyCallbacks): Promise<void> {
    let stream: MediaStream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment", width: { ideal: 640 }, height: { ideal: 480 } },
        audio: false,
      });
    } catch {
      cb.onSensorError("camera", "Camera unavailable — grant access for stronger entropy.");
      return;
    }
    this.addCleanup(() => {
      for (const t of stream.getTracks()) t.stop();
    });
    if (this.stopped) return;
    const video = document.createElement("video");
    video.className = "scanner";
    video.setAttribute("playsinline", "");
    video.muted = true;
    video.srcObject = stream;
    container.append(video);
    this.addCleanup(() => video.remove());
    try {
      await video.play();
    } catch {
      cb.onSensorError("camera", "Camera preview failed to start.");
    }
    if (this.stopped) return;

    const canvas = document.createElement("canvas");
    canvas.width = CAMERA_SIDE;
    canvas.height = CAMERA_SIDE;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });

    const timer = setInterval(() => {
      if (!ctx || video.readyState !== video.HAVE_ENOUGH_DATA) return;
      ctx.drawImage(video, 0, 0, CAMERA_SIDE, CAMERA_SIDE);
      const image = ctx.getImageData(0, 0, CAMERA_SIDE, CAMERA_SIDE);
      // Strip the constant alpha channel — only real pixel data enters the pool.
      const rgb = new Uint8Array(CAMERA_SIDE * CAMERA_SIDE * 3);
      for (let i = 0, j = 0; i < image.data.length; i += 4) {
        rgb[j++] = image.data[i]!;
        rgb[j++] = image.data[i + 1]!;
        rgb[j++] = image.data[i + 2]!;
      }
      this.absorb("camera", rgb, cb);
    }, CAMERA_INTERVAL_MS);

    this.addCleanup(() => clearInterval(timer));
  }

  private async startMicrophone(cb: CeremonyCallbacks): Promise<void> {
    let stream: MediaStream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false },
        video: false,
      });
    } catch {
      cb.onSensorError("microphone", "Microphone unavailable — grant access for stronger entropy.");
      return;
    }
    this.addCleanup(() => {
      for (const t of stream.getTracks()) t.stop();
    });
    if (this.stopped) return;
    const audioCtx = new AudioContext();
    const sourceNode = audioCtx.createMediaStreamSource(stream);
    const analyser = audioCtx.createAnalyser();
    analyser.fftSize = 2048;
    sourceNode.connect(analyser);
    const buf = new Uint8Array(analyser.fftSize);

    const timer = setInterval(() => {
      analyser.getByteTimeDomainData(buf);
      // Copy: addSample zeroizes its input, and `buf` is reused.
      this.absorb("microphone", buf.slice(), cb);
      let sum = 0;
      for (const v of buf) sum += Math.abs(v - 128);
      cb.onMicLevel(Math.min(1, sum / buf.length / 24));
    }, MIC_INTERVAL_MS);

    this.addCleanup(() => {
      clearInterval(timer);
      sourceNode.disconnect();
      void audioCtx.close();
    });
  }

  private startPointer(cb: CeremonyCallbacks): void {
    let buffer: number[] = [];
    const onMove = (e: PointerEvent) => {
      const t = performance.now();
      buffer.push(
        e.clientX & 0xff,
        (e.clientX >> 8) & 0xff,
        e.clientY & 0xff,
        (e.clientY >> 8) & 0xff,
        Math.abs(e.movementX) & 0xff,
        Math.abs(e.movementY) & 0xff,
        Math.floor(t) & 0xff,
        Math.floor(t * 1000) & 0xff, // sub-millisecond jitter
      );
      if (buffer.length >= POINTER_BATCH) {
        this.absorb("touch", new Uint8Array(buffer), cb);
        buffer = [];
      }
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerdown", onMove);
    this.cleanups.push(() => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerdown", onMove);
    });
  }

  private startMotion(cb: CeremonyCallbacks): void {
    let buffer: number[] = [];
    const onMotion = (e: DeviceMotionEvent) => {
      const a = e.accelerationIncludingGravity;
      if (!a || a.x === null || a.y === null || a.z === null) return;
      for (const v of [a.x, a.y, a.z]) {
        const scaled = Math.floor(Math.abs(v) * 4096);
        buffer.push(scaled & 0xff, (scaled >> 8) & 0xff);
      }
      if (buffer.length >= POINTER_BATCH) {
        this.absorb("accelerometer", new Uint8Array(buffer), cb);
        buffer = [];
      }
    };
    window.addEventListener("devicemotion", onMotion);
    this.cleanups.push(() => window.removeEventListener("devicemotion", onMotion));
  }

  /** Extract the seed entropy (throws if the sensor target is unmet). */
  extract(bytes: 16 | 20 | 24 | 28 | 32): Uint8Array {
    return this.pool.extract(bytes);
  }

  /** Stop all sensors and zeroize the pool if it was not extracted. */
  stop(destroyPool: boolean): void {
    this.stopped = true;
    for (const fn of this.cleanups) fn();
    this.cleanups = [];
    if (destroyPool) this.pool.destroy();
  }
}
