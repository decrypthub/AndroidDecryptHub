((scope) => {
  function mount(root, client, openSettings) {
    root.innerHTML = `
      <h2 id="awQuickTitle">快速开始</h2>
      <ol class="aw-quick-steps">
        <li>
          <h3>核对旧配置</h3>
          <p>升级前备份原 Host 数据目录和手机上的 ADH 配置。升级后沿用原 Host 数据目录，在 ADH Manager 核对应用范围。</p>
          <button type="button" id="awQuickSettings">查看 Host 配置</button>
        </li>
        <li>
          <h3>确认设备连接</h3>
          <p>用配套 CLI 连接设备后，在这里检查 Host 当前已验证的连接。</p>
          <div class="aw-row">
            <button type="button" id="awQuickCheck">检查设备连接</button>
            <label id="awQuickConnectionLabel" hidden>设备连接 <select id="awQuickConnection"></select></label>
          </div>
          <p id="awQuickStatus" class="aw-muted" role="status"></p>
        </li>
        <li>
          <h3>读取首条诊断结果</h3>
          <p>从所选连接读取设备信息。隔离沙盒的回执会标明来源。</p>
          <button type="button" id="awQuickRead" disabled>读取诊断结果</button>
          <p id="awQuickOutcome" role="status"></p>
          <pre id="awQuickReceipt" aria-label="设备诊断回执" hidden></pre>
        </li>
      </ol>`;

    const get = id => root.querySelector('#' + id);
    const check = get('awQuickCheck');
    const select = get('awQuickConnection');
    const selection = get('awQuickConnectionLabel');
    const read = get('awQuickRead');
    const status = get('awQuickStatus');
    const outcome = get('awQuickOutcome');
    const receipt = get('awQuickReceipt');
    const connections = new Map();
    let busy = false;

    function updateButtons() {
      check.disabled = busy;
      select.disabled = busy;
      read.disabled = busy || !connections.has(select.value);
    }

    function clearReceipt() {
      outcome.textContent = '';
      receipt.textContent = '';
      receipt.hidden = true;
    }

    get('awQuickSettings').onclick = openSettings;
    select.onchange = () => {
      clearReceipt();
      updateButtons();
    };

    check.onclick = async () => {
      const previous = select.value;
      clearReceipt();
      connections.clear();
      select.replaceChildren();
      selection.hidden = true;
      status.textContent = '正在检查连接…';
      busy = true;
      updateButtons();
      try {
        const {value} = await client.request('/api/devices?action=list');
        for (const device of value.devices) {
          for (const connection of device.connections) {
            if (!connection.online || !connection.identityVerified) continue;
            connections.set(connection.connectionId, connection);
            const transport = connection.transport === 'lan' ? 'LAN' : 'USB';
            const label = `${transport} · ${device.deviceId.slice(0, 8)} · ${connection.connectionId.slice(0, 8)}`;
            select.add(new Option(label, connection.connectionId));
          }
        }
        if (!connections.size) {
          status.textContent = 'Host 当前没有已验证的在线设备连接。连接设备后再检查。';
          return;
        }
        if (connections.size > 1) select.add(new Option('选择设备连接', ''), 0);
        select.value = connections.has(previous) ? previous : select.options[0].value;
        selection.hidden = false;
        status.textContent = `本次检查找到 ${connections.size} 条已验证的在线连接。`;
      } catch (error) {
        connections.clear();
        status.textContent = `无法读取设备连接（${error.code || '响应异常'}）。请确认 Host 在线后重试。`;
      } finally {
        busy = false;
        updateButtons();
      }
    };

    read.onclick = async () => {
      const selected = connections.get(select.value);
      if (!selected) return;
      clearReceipt();
      outcome.textContent = '正在读取诊断结果…';
      busy = true;
      updateButtons();
      try {
        const {deviceId, connectionId} = selected;
        const query = new URLSearchParams({action: 'info', deviceId, connectionId});
        const {value} = await client.request('/api/devices?' + query);
        const info = value.result?.info;
        if (value.deviceId !== deviceId || value.connectionId !== connectionId || typeof info?.model !== 'string') {
          throw new Error('Invalid device receipt');
        }
        const source = info.synthetic === true ? '隔离沙盒' : '已连接设备';
        receipt.textContent = JSON.stringify({
          source, deviceId, connectionId, model: info.model, android: info.android, stateRevision: value.result.stateRevision,
        }, null, 2);
        receipt.hidden = false;
        outcome.textContent = `${source}诊断已返回`;
      } catch (error) {
        outcome.textContent = `诊断读取未完成（${error.code || '回执异常'}）。请重新检查设备连接。`;
      } finally {
        busy = false;
        updateButtons();
      }
    };
  }

  scope.AdhQuickStart = {mount};
})(globalThis);
