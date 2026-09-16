#!/usr/bin/env bash
# v3.6 optional phone automation: tree-first observation, screenshot fallback, semantic and
# normalized-coordinate actions over MCP.
#
# This is an opt-in device feature. The script SKIPs (exit 0) unless the ADH AccessibilityService
# bridge is connected, so CI and machines without the optional service stay green.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/verify_common.sh"
verify_resolve_env
STATE="$(adb -s "$SERIAL" get-state 2>/dev/null | tr -d '\r')"

if [ "$STATE" != "device" ]; then
  echo "SKIP  v3.6 automation — no device"
  exit 0
fi

verify_sandbox_alive
if [ -z "$ALIVE" ]; then echo "❌ v3.6 automation — sandbox not alive"; exit 1; fi

BRIDGE="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
try {
  const r = await (await fetch(`${base}/api/automation/status`)).json();
  console.log(r.bridge?.connected ? 'connected' : 'offline');
} catch { console.log('offline'); }
EOF
)"

if [ "$BRIDGE" != "connected" ]; then
  echo "SKIP  v3.6 automation — AccessibilityService bridge not connected (optional feature)"
  exit 0
fi

# The acceptance drives the sandbox UI, so put it in front first (same setup verify_all does).
# No install and no force-stop: if the foreground is not the sandbox, later observe checks fail.
adb -s "$SERIAL" shell am start -n com.adh.sandbox/.MainActivity >/dev/null 2>&1
sleep 2

SERVICE="com.adh.manager/com.adh.manager.automation.AdhAutomationAccessibilityService"
ENABLED="$(adb -s "$SERIAL" shell settings get secure enabled_accessibility_services 2>/dev/null | tr -d '\r')"
if [[ "$ENABLED" != *"$SERVICE"* ]]; then
  echo "SKIP  v3.6 automation — AccessibilityService is not enabled (optional feature)"
  exit 0
fi

OUT="$(node - "$BASE" <<'EOF'
const base = process.argv[2];
const checks = [];
let original = null;
let rpcId = 1;

function chk(label, ok, detail = '') {
  checks.push([label, !!ok]);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
}

async function postJson(path, body) {
  const response = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  return await response.json();
}

async function getJson(path) {
  return await (await fetch(`${base}${path}`)).json();
}

async function rpc(method, params) {
  const response = await postJson('/mcp', { jsonrpc: '2.0', id: rpcId++, method, params });
  if (response.error) throw new Error(response.error.message || JSON.stringify(response.error));
  return response.result;
}

async function callTool(name, args) {
  const result = await rpc('tools/call', { name, arguments: args });
  if (result?.isError) throw new Error(result.content?.[0]?.text || `${name} failed`);
  return result;
}

function parseTree(result) {
  const text = result.content?.find((item) => item.type === 'text')?.text;
  return JSON.parse(text);
}

function selectedTab(tree) {
  return tree.nodes?.find((node) => node.selected && node.contentDescription)?.contentDescription ?? '';
}

function tabNode(tree, label) {
  return tree.nodes?.find((node) => node.contentDescription === label && node.actions?.includes('click'));
}

try {
  const config = await getJson('/api/config');
  original = JSON.parse(JSON.stringify(config.settings.automation));
  const initialList = await rpc('tools/list', {});
  const initialNames = new Set((initialList.tools || []).map((tool) => tool.name));
  if (!original.enabled) chk('phone_* tools are hidden while automation is disabled', !initialNames.has('phone_observe') && !initialNames.has('phone_act'));
  await postJson('/api/config', { automation: { enabled: true, screenshot: true, packages: ['com.adh.sandbox'], maxNodes: 300, screenshotMaxDimension: 1280 } });

  const list = await rpc('tools/list', {});
  const names = new Set((list.tools || []).map((tool) => tool.name));
  chk('phone_observe is exposed when automation is enabled', names.has('phone_observe'));
  chk('phone_find is exposed when automation is enabled', names.has('phone_find'));
  chk('phone_wait is exposed when automation is enabled', names.has('phone_wait'));
  chk('phone_app is exposed when automation is enabled', names.has('phone_app'));
  chk('phone_device is exposed when automation is enabled', names.has('phone_device'));
  chk('phone_task is exposed when automation is enabled', names.has('phone_task'));
  chk('phone_act is exposed when automation is enabled', names.has('phone_act'));

  // Restarting the sandbox re-creates its process (and its agent session), so it must happen
  // BEFORE the tree snapshot every later ref-based check depends on.
  const reopened = parseTree(await callTool('phone_app', { action: 'restart', package: 'com.adh.sandbox' }));
  chk('phone_app restart verifies the app really reached the foreground', reopened.verified === true && reopened.foreground === 'com.adh.sandbox', `verified=${reopened.verified} foreground=${reopened.foreground} warning=${reopened.warning ?? '-'}`);

  const observe = await callTool('phone_observe', { mode: 'tree', includeScreenshot: false, maxNodes: 80 });
  const tree = parseTree(observe);
  chk('observe returns the AccessibilityService tree', tree.mode === 'tree', `mode=${tree.mode}`);
  chk('observe is pinned to the sandbox package', tree.activePackage === 'com.adh.sandbox', `active=${tree.activePackage}`);
  chk('tree contains actionable nodes', Array.isArray(tree.nodes) && tree.nodes.length > 0, `nodes=${tree.nodes?.length ?? 0}`);
  chk('observe reports truncation state', tree.truncated === false, `truncated=${tree.truncated}`);

  const power = await callTool('phone_device', { action: 'status' });
  const powerData = JSON.parse(power.content?.find((item) => item.type === 'text')?.text);
  chk('phone_device reports a boolean screen state', typeof powerData.interactive === 'boolean' && typeof powerData.locked === 'boolean', `interactive=${powerData.interactive} locked=${powerData.locked}`);

  const task = await callTool('phone_task', { steps: [
    { type: 'device', args: { action: 'status' } },
    { type: 'wait', args: { activePackage: 'com.adh.sandbox', timeoutMs: 5000, intervalMs: 150, maxNodes: 120 } },
    { type: 'find', args: { contentDescription: '加解密', limit: 3, maxNodes: 120 } },
  ] });
  const taskData = JSON.parse(task.content?.find((item) => item.type === 'text')?.text);
  chk('phone_task runs a multi-step sequence', taskData.ok === true && taskData.steps?.length === 3, `ok=${taskData.ok} steps=${taskData.steps?.length ?? 0}`);

  const timeoutTask = await callTool('phone_task', { steps: [
    { type: 'wait', args: { contentDescription: 'ADH_NO_SUCH_NODE_v1', timeoutMs: 900, intervalMs: 150, maxNodes: 60 } },
  ] });
  const timeoutTaskData = JSON.parse(timeoutTask.content?.find((item) => item.type === 'text')?.text);
  chk('phone_task fails a timed-out wait step instead of continuing', timeoutTaskData.ok === false && timeoutTaskData.failedStep === 0 && /wait_timeout/.test(timeoutTaskData.steps?.[0]?.error ?? ''), `ok=${timeoutTaskData.ok} error=${timeoutTaskData.steps?.[0]?.error}`);

  const activeWait = await callTool('phone_wait', { activePackage: 'com.adh.sandbox', timeoutMs: 5000, intervalMs: 150, maxNodes: 120 });
  const activeWaitData = JSON.parse(activeWait.content?.find((item) => item.type === 'text')?.text);
  chk('phone_wait matches the active package', activeWaitData.matched === true, `active=${activeWaitData.activePackage}`);

  const found = await callTool('phone_find', { contentDescription: '加解密', limit: 5, maxNodes: 120 });
  const foundData = JSON.parse(found.content?.find((item) => item.type === 'text')?.text);
  chk('phone_find returns a compact selector match', foundData.count > 0, `count=${foundData.count}`);

  const current = selectedTab(tree);
  const targetLabel = ['状态', '加解密', '网络·文件', '脱壳', '日志'].find((label) => label !== current && tabNode(tree, label));
  chk('sandbox exposes a different tab to click', !!targetLabel, `current=${current || '(none)'} target=${targetLabel || '(none)'}`);

  if (targetLabel) {
    const target = tabNode(tree, targetLabel);
    const action = await callTool('phone_act', {
      snapshotId: tree.snapshotId,
      action: 'tap',
      ref: target.ref,
      observeAfter: true,
      includeScreenshot: false,
      maxNodes: 80,
    });
    const actionText = action.content?.find((item) => item.type === 'text')?.text;
    const actionResult = JSON.parse(actionText);
    chk('semantic ref action is accepted', actionResult.target === 'ref' && actionResult.ref === target.ref, `target=${actionResult.target}`);
    const afterText = action.content?.filter((item) => item.type === 'text')[1]?.text;
    const after = afterText ? JSON.parse(afterText) : null;
    chk('semantic ref changes the selected tab', selectedTab(after) === targetLabel, `selected=${selectedTab(after)}`);
  }

  const selectorObserve = await callTool('phone_observe', { mode: 'tree', includeScreenshot: false, maxNodes: 80 });
  const selectorTree = parseTree(selectorObserve);
  const selectorCurrent = selectedTab(selectorTree);
  const selectorTarget = ['状态', '加解密', '网络·文件', '脱壳', '日志'].find((label) => label !== selectorCurrent && tabNode(selectorTree, label));
  chk('sandbox exposes a selector action target', !!selectorTarget, `current=${selectorCurrent || '(none)'} target=${selectorTarget || '(none)'}`);
  if (selectorTarget) {
    const selectorActionResult = await callTool('phone_act', { action: 'tap', contentDescription: selectorTarget, observeAfter: true, includeScreenshot: false, maxNodes: 80 });
    const selectorResult = JSON.parse(selectorActionResult.content?.find((item) => item.type === 'text')?.text);
    chk('selector action resolves to a ref', selectorResult.target === 'ref', `target=${selectorResult.target}`);
    const selectorAfterText = selectorActionResult.content?.filter((item) => item.type === 'text')[1]?.text;
    const selectorAfter = selectorAfterText ? JSON.parse(selectorAfterText) : null;
    chk('selector action changes the selected tab', selectedTab(selectorAfter) === selectorTarget, `selected=${selectedTab(selectorAfter)}`);
    const wait = await callTool('phone_wait', { contentDescription: selectorTarget, timeoutMs: 5000, intervalMs: 150, maxNodes: 120 });
    const waitData = JSON.parse(wait.content?.find((item) => item.type === 'text')?.text);
    chk('phone_wait matches a visible selector', waitData.matched === true, `matched=${waitData.matched}`);
  }

  // ---- agent-signal waits: wait on process-internal ground truth, not just UI ------------
  const agents = await getJson('/api/agents');
  const liveSandbox = agents
    .filter((session) => session.package === 'com.adh.sandbox' && session.online)
    .sort((a, b) => b.connectedAt - a.connectedAt)[0];
  const captureEnabled = (await getJson('/api/config')).settings?.capture?.enabled === true;
  if (!liveSandbox || !captureEnabled) {
    console.log(`SKIP: agent-signal wait — ${!liveSandbox ? 'no live com.adh.sandbox agent session' : 'capture disabled'}`);
  } else {
    const signalTree = parseTree(await callTool('phone_observe', { mode: 'tree', includeScreenshot: false, maxNodes: 120 }));
    if (selectedTab(signalTree) !== '加解密') {
      await callTool('phone_act', { action: 'tap', contentDescription: '加解密', includeScreenshot: false, maxNodes: 80 });
    }
    const ready = parseTree(await callTool('phone_observe', { mode: 'tree', includeScreenshot: false, maxNodes: 120 }));
    if (!ready.nodes?.some((node) => node.text === 'AES-CBC')) {
      console.log('SKIP: agent-signal wait — sandbox 加解密 button is not on screen');
    } else {
      const signalTap = parseTree(await callTool('phone_act', { action: 'tap', text: 'AES-CBC' }));
      chk('phone_act returns a pre-action agent cursor', typeof signalTap.cursorBefore?.captureId === 'number', `cursor=${JSON.stringify(signalTap.cursorBefore)}`);
      const signalWait = parseTree(await callTool('phone_wait', {
        captureCategory: 'crypto',
        captureContains: 'ADH手动_AES_#',
        afterCaptureId: signalTap.cursorBefore?.captureId,
        timeoutMs: 8000,
        intervalMs: 200,
      }));
      chk('phone_wait matches the crypto signal caused by the tap', signalWait.matched === true && signalWait.kind === 'capture' && /AES/.test(signalWait.item?.algo ?? ''), `algo=${signalWait.item?.algo} elapsed=${signalWait.elapsedMs}`);
      chk('agent wait decodes the captured plaintext', String(signalWait.item?.text ?? '').includes('ADH手动_AES_#'), `text=${JSON.stringify(signalWait.item?.text ?? null)}`);
      const missTap = parseTree(await callTool('phone_act', { action: 'tap', text: 'AES-CBC' }));
      const signalMiss = parseTree(await callTool('phone_wait', {
        captureCategory: 'crypto',
        captureContains: 'ADH_NO_SUCH_MARKER_v1',
        afterCaptureId: missTap.cursorBefore?.captureId,
        timeoutMs: 4000,
        intervalMs: 200,
      }));
      chk('agent wait times out loudly when the marker never arrives', signalMiss.matched === false && signalMiss.timedOut === true);
      // The sandbox keeps a live crypto driver running, so a 4s window can hold more captures
      // than the (bounded) sample list. Assert the diagnosis itself: totals + shaped samples.
      const sawShaped = Array.isArray(signalMiss.saw?.captures) && signalMiss.saw.captures.length > 0
        && signalMiss.saw.captures.every((item) => typeof item.id === 'number' && typeof item.category === 'string' && typeof item.preview === 'string');
      chk('agent wait timeout reports the signals it did see', (signalMiss.saw?.totals?.captures ?? 0) >= 1 && sawShaped && typeof signalMiss.cursor?.captureId === 'number', `saw=${JSON.stringify(signalMiss.saw?.totals)} sample=${signalMiss.saw?.captures?.[0]?.algo ?? '-'} events=${signalMiss.saw?.totals?.events ?? 0}`);
    }
  }

  // ---- reusable recipes: save -> list -> run -> delete -----------------------------------
  const recipe = parseTree(await callTool('phone_skill', {
    action: 'save',
    name: 'v36-crypto-tab',
    description: 'acceptance recipe',
    overwrite: true,
    steps: [
      { type: 'wait', args: { activePackage: 'com.adh.sandbox', timeoutMs: 4000, intervalMs: 200, maxNodes: 120 } },
      { type: 'act', args: { action: 'tap', contentDescription: '加解密', maxNodes: 120 } },
    ],
  }));
  chk('phone_skill saves a validated recipe', recipe.saved === true && recipe.steps === 2, `steps=${recipe.steps}`);
  const recipes = parseTree(await callTool('phone_skill', { action: 'list' }));
  chk('phone_skill lists the saved recipe', (recipes.skills ?? []).some((skill) => skill.name === 'v36-crypto-tab'));
  const replay = parseTree(await callTool('phone_skill', { action: 'run', name: 'v36-crypto-tab' }));
  chk('phone_skill replays the recipe through the task runner', replay.ok === true && replay.steps?.length === 2, `ok=${replay.ok} steps=${replay.steps?.length ?? 0}`);
  let skillRejected = '';
  try {
    await callTool('phone_skill', { action: 'save', name: 'v36-bad', overwrite: true, steps: [{ type: 'shell', args: { cmd: 'id' } }] });
  } catch (error) {
    skillRejected = error.message || String(error);
  }
  chk('phone_skill rejects step types outside the primitive set', /unsupported type/.test(skillRejected), skillRejected);
  const removedRecipe = parseTree(await callTool('phone_skill', { action: 'delete', name: 'v36-crypto-tab' }));
  chk('phone_skill deletes the recipe', removedRecipe.deleted === true);

  const paramRecipe = parseTree(await callTool('phone_skill', {
    action: 'save',
    name: 'v36-open-tab',
    description: 'parametrised tab opener',
    overwrite: true,
    params: ['tab'],
    steps: [
      { id: 'find_tab', type: 'find', args: { contentDescription: '{{input.tab}}', maxNodes: 120, limit: 3 } },
      { type: 'act', args: { action: 'tap', snapshotId: '{{find_tab.snapshotId}}', ref: '{{find_tab.nodes.0.ref}}', maxNodes: 80 } },
      { type: 'wait', args: { contentDescription: '{{input.tab}}', timeoutMs: 3000, intervalMs: 200, maxNodes: 120 } },
    ],
  }));
  chk('phone_skill saves a parameterised recipe', paramRecipe.saved === true && (paramRecipe.params ?? []).includes('tab'), `params=${JSON.stringify(paramRecipe.params)}`);
  const paramRun = parseTree(await callTool('phone_skill', { action: 'run', name: 'v36-open-tab', inputs: { tab: '脱壳' } }));
  chk('phone_skill feeds inputs into the step templates', paramRun.ok === true, `ok=${paramRun.ok} inputs=${JSON.stringify(paramRun.inputs)}`);
  let paramMissing = '';
  try {
    await callTool('phone_skill', { action: 'run', name: 'v36-open-tab' });
  } catch (error) {
    paramMissing = error.message || String(error);
  }
  chk('phone_skill refuses to run without a required input', /skill_missing_input/.test(paramMissing), paramMissing);
  await callTool('phone_skill', { action: 'delete', name: 'v36-open-tab' });

  // ---- step templating: a find result feeds the next step without another round trip -----
  const chained = parseTree(await callTool('phone_task', { steps: [
    { id: 'find_tab', type: 'find', args: { contentDescription: '状态', maxNodes: 120, limit: 3 } },
    { id: 'tap_tab', type: 'act', args: { action: 'tap', snapshotId: '{{find_tab.snapshotId}}', ref: '{{find_tab.nodes.0.ref}}', maxNodes: 80 } },
    { type: 'wait', args: { contentDescription: '状态', timeoutMs: 3000, intervalMs: 200, maxNodes: 120 } },
  ] }));
  chk('phone_task chains a find result into act via {{id.path}}', chained.ok === true && chained.steps?.length === 3, `ok=${chained.ok} steps=${chained.steps?.length ?? 0}`);
  const chainedFail = parseTree(await callTool('phone_task', { steps: [
    { type: 'act', args: { action: 'tap', snapshotId: '{{missing.snapshotId}}', ref: '{{missing.ref}}' } },
  ] }));
  chk('an unknown template reference fails the step loudly', chainedFail.ok === false && /template_unknown_step/.test(chainedFail.steps?.[0]?.error ?? ''), `ok=${chainedFail.ok} error=${chainedFail.steps?.[0]?.error}`);

  // ---- compact text view: same tree, far fewer tokens, refs stay actionable -------------
  const textView = await callTool('phone_observe', { mode: 'text', maxNodes: 40 });
  const textPayload = textView.content?.find((item) => item.type === 'text')?.text ?? '';
  chk('phone_observe mode=text renders a compact screen view', textPayload.startsWith('screen: com.adh.sandbox') && /^\[n\d+\] /m.test(textPayload), `bytes=${textPayload.length}`);
  const textSnapshot = /snapshot=([^ ]+)/.exec(textPayload)?.[1];
  const textTabRef = /\[(n\d+)\] LinearLayout desc="加解密"/.exec(textPayload)?.[1];
  chk('text view exposes a ref for the tab', !!textSnapshot && !!textTabRef, `snapshot=${textSnapshot ?? '-'} ref=${textTabRef ?? '-'}`);
  if (textSnapshot && textTabRef) {
    const textTap = parseTree(await callTool('phone_act', { snapshotId: textSnapshot, action: 'tap', ref: textTabRef, includeScreenshot: false, maxNodes: 60 }));
    // A ref resolves to ACTION_CLICK when the node is clickable and to a node-center gesture
    // otherwise, so assert the observable effect instead of the internal target label.
    const afterTextTap = parseTree(await callTool('phone_observe', { mode: 'tree', includeScreenshot: false, maxNodes: 80 }));
    chk('refs taken from the text view are directly actionable', selectedTab(afterTextTap) === '加解密', `target=${textTap.target} ref=${textTap.ref} selected=${selectedTab(afterTextTap)}`);
  }

  const visual = await callTool('phone_observe', { mode: 'visual', maxNodes: 20 });
  const image = visual.content?.find((item) => item.type === 'image');
  chk('visual fallback returns a JPEG image', image?.mimeType === 'image/jpeg' && (image?.data?.length ?? 0) > 1000, `bytes=${image?.data?.length ?? 0}`);

  const beforeCoordinate = await callTool('phone_observe', { mode: 'tree', includeScreenshot: false, maxNodes: 80 });
  const beforeTree = parseTree(beforeCoordinate);
  const beforeLabel = selectedTab(beforeTree);
  const coordinateTarget = ['状态', '加解密', '网络·文件', '脱壳', '日志'].find((label) => label !== beforeLabel && tabNode(beforeTree, label));
  chk('sandbox exposes a different coordinate target', !!coordinateTarget, `current=${beforeLabel || '(none)'} target=${coordinateTarget || '(none)'}`);
  if (coordinateTarget) {
    const node = tabNode(beforeTree, coordinateTarget);
    const [left, top, right, bottom] = node.bounds;
    const x = ((left + right) / 2) / beforeTree.screen.width;
    const y = ((top + bottom) / 2) / beforeTree.screen.height;
    const action = await callTool('phone_act', {
      action: 'tap',
      x,
      y,
      coordinateSpace: 'normalized',
      observeAfter: true,
      includeScreenshot: false,
      maxNodes: 80,
    });
    const actionText = action.content?.find((item) => item.type === 'text')?.text;
    const actionResult = JSON.parse(actionText);
    chk('normalized coordinate action is accepted', actionResult.target === 'coordinate', `target=${actionResult.target}`);
    const afterText = action.content?.filter((item) => item.type === 'text')[1]?.text;
    const after = afterText ? JSON.parse(afterText) : null;
    chk('normalized coordinate changes the selected tab', selectedTab(after) === coordinateTarget, `selected=${selectedTab(after)}`);
  }

  const swipe = await callTool('phone_act', {
    action: 'swipe',
    x: 0.5,
    y: 0.75,
    x2: 0.5,
    y2: 0.35,
    durationMs: 320,
    coordinateSpace: 'normalized',
  });
  const swipeText = swipe.content?.[0]?.text;
  chk('normalized swipe is accepted', JSON.parse(swipeText).action === 'swipe');
  // ---- system shade + text input: two surfaces an AI driver needs ------------------------

  // ---- system shade + text input: two surfaces an AI driver needs ------------------------
  const scope = await getJson('/api/config');
  const basePackages = scope.settings.automation.packages;

  // (b) set_text against the sandbox's own probe field. It is our fixture on purpose: the
  // launcher-search detour (and the module-manager search box) both depend on foreign UI that
  // shifts between ROM builds, which made the acceptance flaky rather than the feature.
  const probeField = 'com.adh.sandbox:id/adh_input_probe';
  try {
    const locate = async () => parseTree(await callTool('phone_find', { resourceId: probeField, maxNodes: 150, limit: 4 }));
    let field = await locate();
    if (!(field.nodes ?? []).length && field.activePackage === 'com.adh.sandbox') {
      await callTool('phone_act', { action: 'tap', contentDescription: '状态', maxNodes: 150 });
      await new Promise((resolve) => setTimeout(resolve, 800));
      field = await locate();
    }
    chk('sandbox exposes the text-input probe field', (field.nodes ?? []).length > 0, `count=${field.count} active=${field.activePackage}`);
    if ((field.nodes ?? []).length) {
      const marker = 'ADH_SET_TEXT_v1';
      const typed = parseTree(await callTool('phone_act', { action: 'set_text', resourceId: probeField, text: marker, maxNodes: 150 }));
      chk('set_text resolves the field by id and dispatches', typed.target === 'ref', `target=${typed.target} ref=${typed.ref}`);
      await new Promise((resolve) => setTimeout(resolve, 600));
      const after = await locate();
      const value = (after.nodes ?? [])[0]?.text;
      chk('set_text value is readable back from the field', value === marker, `value=${JSON.stringify(value ?? null)}`);
    }
  } catch (error) {
    chk('text input acceptance path completed', false, error.message || String(error));
  }
  // (a) the notification shade has to be readable through the tree
  await postJson('/api/config', { automation: { ...scope.settings.automation, packages: [...new Set([...basePackages, 'com.android.systemui'])] } });
  try {
    await callTool('phone_act', { action: 'global', key: 'notifications' });
    await new Promise((resolve) => setTimeout(resolve, 600));
    const shade = parseTree(await callTool('phone_observe', { mode: 'tree', includeScreenshot: false, maxNodes: 200 }));
    const readable = (shade.nodes ?? []).filter((node) => ((node.text ?? '') + (node.contentDescription ?? '')).length > 0).length;
    chk('notification shade is readable through the tree', shade.activePackage === 'com.android.systemui' && readable > 0, `active=${shade.activePackage} nodes=${shade.nodes?.length ?? 0} readable=${readable}`);
    await callTool('phone_act', { action: 'global', key: 'back' });
  } catch (error) {
    chk('notification shade acceptance path completed', false, error.message || String(error));
    await callTool('phone_act', { action: 'global', key: 'back' }).catch(() => {});
  } finally {
    await postJson('/api/config', { automation: { ...scope.settings.automation, packages: basePackages } });
  }

  // (b) gesture-driven scroll-until-found: ACTION_SCROLL is rejected by pagers and custom
  // lists, a real swipe is not. Guarded on the launcher being allowlisted on this host.
  if ((original?.packages ?? []).includes('com.android.launcher')) {
    await postJson('/api/config', { automation: { ...scope.settings.automation, packages: [...new Set([...basePackages, 'com.android.launcher', 'com.android.systemui'])] } });
    try {
      await callTool('phone_act', { action: 'global', key: 'home' });
      await new Promise((resolve) => setTimeout(resolve, 800));
      const beforeHome = await callTool('phone_observe', { mode: 'text', maxNodes: 60 });
      const labelsOf = (text) => (text.split('\n').map((line) => /TextView "([^"]*)"/.exec(line)?.[1]).filter(Boolean).slice(0, 6).join('/'));
      const beforeLabels = labelsOf(beforeHome.content?.find((item) => item.type === 'text')?.text ?? '');
      const swept = parseTree(await callTool('phone_wait', {
        activePackage: 'com.android.launcher',
        textContains: '__ADH_NO_SUCH_LABEL__',
        scroll: true,
        scrollMode: 'gesture',
        axis: 'horizontal',
        maxScrolls: 2,
        timeoutMs: 2500,
        intervalMs: 250,
        maxNodes: 120,
      }));
      const afterHome = await callTool('phone_observe', { mode: 'text', maxNodes: 60 });
      const afterLabels = labelsOf(afterHome.content?.find((item) => item.type === 'text')?.text ?? '');
      chk('phone_wait gesture scroll dispatches swipes where ACTION_SCROLL is rejected', swept.timedOut === true && swept.scrolls >= 1, `scrolls=${swept.scrolls} pageChanged=${beforeLabels !== afterLabels} before=${beforeLabels} after=${afterLabels}`);
    } catch (error) {
      chk('gesture scroll acceptance path completed', false, error.message || String(error));
    } finally {
      await postJson('/api/config', { automation: { ...scope.settings.automation, packages: basePackages } });
    }
  } else {
    console.log('SKIP: gesture scroll — com.android.launcher is not in the automation allowlist');
  }

} catch (error) {
  chk('automation acceptance path completed', false, error.message || String(error));
} finally {
  if (original) {
    try {
      await postJson('/api/config', { automation: original });
      if (!original.enabled) {
        const restoredList = await rpc('tools/list', {});
        const restoredNames = new Set((restoredList.tools || []).map((tool) => tool.name));
        chk('phone_* tools are hidden again after restore', !restoredNames.has('phone_observe') && !restoredNames.has('phone_act'));
      }
    } catch (error) {
      chk('restore prior automation settings', false, error.message || String(error));
    }
  }
}

console.log(checks.every(([, ok]) => ok) ? 'RESULT:PASS' : 'RESULT:FAIL');
process.exit(checks.every(([, ok]) => ok) ? 0 : 1);
EOF
)"

echo "$OUT"
if grep -q 'RESULT:PASS' <<<"$OUT"; then echo "✅ v3.6 phone automation PASS"; exit 0; else echo "❌ v3.6 phone automation FAIL"; exit 1; fi
