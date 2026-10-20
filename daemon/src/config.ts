import { networkInterfaces } from 'node:os';

export const HTTP_PORT = Number(process.env.ADH_HTTP_PORT ?? 8088);
export const AGENT_PORT = Number(process.env.ADH_AGENT_PORT ?? 8761);

const VIRTUAL_NIC = /^(vEthernet|Loopback|WSL|Hyper-V|docker|veth|utun|tun|tap|vmware|virtualbox|vbox|bluetooth|蓝牙|tailscale|zerotier|npcap|wireguard|wintun|hamachi|radmin)/i;

/** A phone on the same Wi-Fi can open this address. Skips loopback, APIPA, and virtual adapters. */
export function isUsefulLanIPv4(name: string, address: string, internal = false): boolean {
  if (internal) return false;
  if (address.startsWith('127.') || address.startsWith('169.254.')) return false;
  if (VIRTUAL_NIC.test(name)) return false;
  return true;
}

function lanIPv4s(): string[] {
  const nics = networkInterfaces();
  const privateAddresses: string[] = [];
  const otherAddresses: string[] = [];
  for (const [name, addresses] of Object.entries(nics)) {
    for (const address of addresses ?? []) {
      if (address.family !== 'IPv4') continue;
      if (!isUsefulLanIPv4(name, address.address, address.internal)) continue;
      const target = /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address.address)
        ? privateAddresses
        : otherAddresses;
      target.push(address.address);
    }
  }
  return [...privateAddresses, ...otherAddresses];
}

export function webUrls() {
  const lan = lanIPv4s().map((ip) => `http://${ip}:${HTTP_PORT}`);
  return { port: HTTP_PORT, local: `http://127.0.0.1:${HTTP_PORT}`, lan };
}
