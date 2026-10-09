import { networkInterfaces } from 'node:os';

export const HTTP_PORT = Number(process.env.ADH_HTTP_PORT ?? 8088);
export const AGENT_PORT = Number(process.env.ADH_AGENT_PORT ?? 8761);

function lanIPv4s(): string[] {
  const nics = networkInterfaces();
  const privateAddresses: string[] = [];
  const otherAddresses: string[] = [];
  for (const [name, addresses] of Object.entries(nics)) {
    for (const address of addresses ?? []) {
      if (address.family !== 'IPv4' || address.internal) continue;
      if (/^(vEthernet|Loopback|WSL|Hyper-V|docker|veth|utun|tun|tap)/i.test(name)) continue;
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
