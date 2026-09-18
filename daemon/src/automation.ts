import net from 'node:net';
import { webUrls } from './config.ts';
import { blockedPackageFromError } from './phone_foreground.ts';
import { recordBlockedPackage } from './phone_blocked.ts';
import { randomUUID } from 'node:crypto';

export interface AutomationCaps {
  tree: boolean;
  screenshot: boolean;
  gestures: boolean;
  setText: boolean;
  maxNodes: number;
}

export interface AutomationDevice {
  deviceId: string;
  model: string;
  sdk: number;
  caps: AutomationCaps;
  connectedAt: number;
  lastSeen: number;
  online: boolean;
}

interface DeviceRecord extends AutomationDevice {
  socket: net.Socket;
}

interface PendingCommand {
  id: string;
  op: string;
  deviceId: string;
  resolve: (value: any) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

const LINE_LIMIT = 16 * 1024 * 1024;
const DEFAULT_CAPS: AutomationCaps = { tree: false, screenshot: false, gestures: false, setText: false, maxNodes: 300 };

function protocolError(code: string, message: string): Error {
  return Object.assign(new Error(message), { code });
}

function parseLine(line: string): any {
  const text = line.trim();
  if (!text) return null;
  if (text.length > LINE_LIMIT) throw protocolError('line_too_large', `automation line exceeds ${LINE_LIMIT} bytes`);
  return JSON.parse(text);
}

export class AutomationHub {
  private server: net.Server | null = null;
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly pending = new Map<string, PendingCommand>();
  private listenPort = 0;
  private listenHost = '127.0.0.1';

  async listen(port: number, host = '127.0.0.1'): Promise<number> {
    if (this.server) return this.listenPort;
    this.listenHost = host;
    const server = net.createServer((socket) => this.onConnection(socket));
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      server.once('error', onError);
      server.listen(port, host, () => {
        server.off('error', onError);
        resolve();
      });
    });
    this.server = server;
    const address = server.address();
    this.listenPort = typeof address === 'object' && address ? address.port : port;
    return this.listenPort;
  }

  async close(): Promise<void> {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(protocolError('automation_closed', 'automation bridge closed'));
    }
    this.pending.clear();
    for (const device of this.devices.values()) device.socket.destroy();
    this.devices.clear();
    const server = this.server;
    this.server = null;
    if (!server) return;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  status() {
    return {
      listening: !!this.server,
      host: this.listenHost,
      port: this.listenPort,
      connected: this.devices.size > 0,
      devices: [...this.devices.values()].map((device) => ({
        deviceId: device.deviceId,
        model: device.model,
        sdk: device.sdk,
        caps: device.caps,
        connectedAt: device.connectedAt,
        lastSeen: device.lastSeen,
        online: device.online,
      })),
      pending: this.pending.size,
    };
  }

  async cmd(op: string, args: Record<string, any> = {}, timeoutMs = 20_000, deviceId?: string): Promise<any> {
    const device = this.selectDevice(deviceId);
    if (!device) throw protocolError('automation_offline', 'no automation device connected; enable the ADH AccessibilityService and ensure adb reverse is active');
    const id = randomUUID();
    const payload = JSON.stringify({ t: 'cmd', id, op, args });
    return await new Promise<any>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(protocolError('automation_timeout', `automation command timed out: ${op}`));
      }, timeoutMs);
      this.pending.set(id, { id, op, deviceId: device.deviceId, resolve, reject, timer });
      device.socket.write(payload + '\n', (error?: Error | null) => {
        if (!error) return;
        clearTimeout(timer);
        this.pending.delete(id);
        reject(protocolError('automation_write_failed', error.message));
      });
    });
  }

  private selectDevice(deviceId?: string): DeviceRecord | null {
    if (deviceId) return this.devices.get(deviceId) ?? null;
    if (this.devices.size === 1) return this.devices.values().next().value as DeviceRecord;
    return null;
  }

  private onConnection(socket: net.Socket) {
    socket.setNoDelay(true);
    let buffer = '';
    let registeredId: string | null = null;
    let helloSeen = false;

    const fail = (error: Error) => {
      socket.write(JSON.stringify({ t: 'error', error: { code: (error as any).code ?? 'protocol_error', message: error.message } }) + '\n');
      socket.destroy();
    };

    socket.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      if (buffer.length > LINE_LIMIT) return fail(protocolError('line_too_large', 'automation receive buffer overflow'));
      for (;;) {
        const newline = buffer.indexOf('\n');
        if (newline < 0) break;
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        try {
          const msg = parseLine(line);
          if (!msg) continue;
          if (msg.t === 'hello') {
            if (helloSeen) continue;
            helloSeen = true;
            const deviceId = String(msg.deviceId || '').trim() || `device-${randomUUID().slice(0, 8)}`;
            registeredId = deviceId;
            const record: DeviceRecord = {
              deviceId,
              model: String(msg.model || 'unknown'),
              sdk: Number(msg.sdk || 0),
              caps: { ...DEFAULT_CAPS, ...(msg.caps || {}) },
              connectedAt: Date.now(),
              lastSeen: Date.now(),
              online: true,
              socket,
            };
            const previous = this.devices.get(deviceId);
            if (previous && previous.socket !== socket) {
              for (const [id, pending] of this.pending) {
                if (pending.deviceId !== deviceId) continue;
                clearTimeout(pending.timer);
                this.pending.delete(id);
                pending.reject(protocolError('automation_replaced', 'automation device reconnected'));
              }
              previous.socket.destroy();
            }
            this.devices.set(deviceId, record);
            // Advertise the host's LAN addresses: a client that got here through adb reverse can
            // remember them and reconnect over Wi-Fi next time instead of needing the cable.
            const lanHosts = webUrls().lan
              .map((url) => url.replace(/^https?:\/\//, '').split('/')[0].split(':')[0])
              .filter((host) => /^[0-9.]+$/.test(host));
            socket.write(JSON.stringify({ t: 'helloAck', deviceId, lanHosts }) + '\n');
            continue;
          }
          if (!helloSeen || !registeredId) continue;
          const device = this.devices.get(registeredId);
          if (device) device.lastSeen = Date.now();
          if (msg.t === 'result' || msg.t === 'error') {
            const pending = this.pending.get(String(msg.id || ''));
            if (!pending) continue;
            clearTimeout(pending.timer);
            this.pending.delete(pending.id);
            // An explicit ok:true is required (v4.92): a truncated or legacy device reply that omits
            // the field used to resolve as a success, so a half-written frame looked like a result.
            if (msg.t === 'result' && msg.ok === true) pending.resolve(msg.result ?? msg);
            else {
              const failure = protocolError(msg.error?.code ?? 'automation_error', msg.error?.message ?? msg.error ?? 'automation command failed');
              // Central allowlist-refusal sink: every phone_* path reports through here, so the
              // settings panel can offer to add the package the AI actually ran into.
              const refused = blockedPackageFromError(failure.message);
              if (refused) recordBlockedPackage(refused);
              pending.reject(failure);
            }
          }
        } catch (error) {
          fail(error as Error);
          return;
        }
      }
    });

    socket.on('close', () => {
      if (!registeredId) return;
      const device = this.devices.get(registeredId);
      if (!device || device.socket !== socket) return;
      device.online = false;
      this.devices.delete(registeredId);
      for (const [id, pending] of this.pending) {
        if (pending.deviceId !== registeredId) continue;
        clearTimeout(pending.timer);
        this.pending.delete(id);
        pending.reject(protocolError('automation_offline', 'automation device disconnected'));
      }
    });

    socket.on('error', () => {
      // close handles registry cleanup; errors are expected during adb reverse teardown.
    });

    setTimeout(() => {
      if (!helloSeen) socket.destroy();
    }, 5_000).unref();
  }
}

export const automation = new AutomationHub();
