/**
 * Screenshot the site through the DevTools protocol, so reveals, fonts and
 * lazy work all settle before the frame is taken. Edge/Chrome only.
 *
 *   node tools/shoot.mjs --url http://127.0.0.1:8770/ --w 1440 --h 900 --out shot.png
 *   node tools/shoot.mjs --url http://127.0.0.1:8770/ --w 1440 --h 900 --full --out full.png
 *   node tools/shoot.mjs --url http://127.0.0.1:8770/ --w 390 --h 844 --mobile --scroll "#record" --out m.png
 *   node tools/shoot.mjs --eval "document.documentElement.scrollWidth" ...
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const EDGE = process.env.EDGE_BIN || "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const PORT = 9333 + Math.floor(Math.random() * 200);

const args = process.argv.slice(2);
const opt = (name, fallback = null) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
};
const flag = (name) => args.includes(`--${name}`);

const url = opt("url", "http://127.0.0.1:8770/");
const width = Number(opt("w", 1440));
const height = Number(opt("h", 900));
const out = opt("out", "shot.png");
const full = flag("full");
const mobile = flag("mobile");
const scrollSel = opt("scroll", null);
const wait = Number(opt("wait", 1400));
const evalExpr = opt("eval", null);

const profile = path.resolve(".cache/cdp-profile", String(PORT));

const proc = spawn(EDGE, [
  "--headless=new",
  "--disable-gpu",
  "--hide-scrollbars",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-extensions",
  `--remote-debugging-port=${PORT}`,
  `--user-data-dir=${profile}`,
  "about:blank",
], { stdio: "ignore" });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getJson(p) {
  const res = await fetch(`http://127.0.0.1:${PORT}${p}`, { method: p.startsWith("/json/new") ? "PUT" : "GET" });
  return res.json();
}

async function waitForDevtools() {
  for (let i = 0; i < 80; i++) {
    try {
      const v = await getJson("/json/version");
      if (v.webSocketDebuggerUrl) return;
    } catch {}
    await sleep(100);
  }
  throw new Error("devtools did not start");
}

function connect(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  const pending = new Map();
  const events = new Map();
  const ready = new Promise((res, rej) => {
    ws.onopen = res;
    ws.onerror = rej;
  });
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    } else if (msg.method) {
      for (const fn of events.get(msg.method) || []) fn(msg.params);
    }
  };
  const send = async (method, params = {}) => {
    await ready;
    const mid = ++id;
    return new Promise((resolve, reject) => {
      pending.set(mid, { resolve, reject });
      ws.send(JSON.stringify({ id: mid, method, params }));
    });
  };
  const once = (method) =>
    new Promise((resolve) => {
      const list = events.get(method) || [];
      const fn = (params) => {
        events.set(method, (events.get(method) || []).filter((f) => f !== fn));
        resolve(params);
      };
      events.set(method, [...list, fn]);
    });
  return { send, once, close: () => ws.close() };
}

try {
  await waitForDevtools();
  const target = await getJson("/json/new?about:blank");
  const cdp = connect(target.webSocketDebuggerUrl);
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Emulation.setDeviceMetricsOverride", {
    width, height, deviceScaleFactor: 1, mobile,
  });
  await cdp.send("Emulation.setEmulatedMedia", {
    features: [{ name: "prefers-reduced-motion", value: "no-preference" }],
  });

  const loaded = cdp.once("Page.loadEventFired");
  await cdp.send("Page.navigate", { url });
  await loaded;
  await sleep(wait);

  let metrics = null;
  if (evalExpr) {
    const r = await cdp.send("Runtime.evaluate", { expression: evalExpr, returnByValue: true, awaitPromise: true });
    metrics = r.result.value;
    console.log(JSON.stringify(metrics, null, 2));
  }

  if (scrollSel) {
    await cdp.send("Runtime.evaluate", {
      expression: `document.querySelector(${JSON.stringify(scrollSel)}).scrollIntoView({block:"start",behavior:"instant"})`,
    });
    await sleep(900);
  }

  const shot = await cdp.send("Page.captureScreenshot", {
    format: "png",
    captureBeyondViewport: full,
    ...(full ? { clip: await cdp.send("Runtime.evaluate", {
      expression: `(() => { const d = document.documentElement; return {x:0,y:0,width:d.scrollWidth,height:d.scrollHeight,scale:1}; })()`,
      returnByValue: true,
    }).then((r) => r.result.value) } : {}),
  });
  fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
  fs.writeFileSync(out, Buffer.from(shot.data, "base64"));
  console.log(`saved ${out}`);
  cdp.close();
} finally {
  proc.kill();
}
