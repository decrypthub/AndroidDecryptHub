((scope) => {
  const M = scope.AdhWorkbenchModel;
  const PAGE_SIZE = 25;
  const titles = new Map([
    ['settings', '保存设置'],
    ['automatic-capture-families', '应用采集设置'],
    ['unpack_package', '一键脱壳'],
  ]);
  const sources = new Map([['panel', '面板'], ['mcp', 'AI 客户端'], ['automatic', '自动执行']]);
  const titleFor = name => titles.get(name) || name;
  const json = value => JSON.stringify(value, null, 2);
  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }
  function button(text, fn, className) {
    const node = element('button', text, className);
    node.type = 'button';
    node.onclick = fn;
    return node;
  }
  function badge(state, implicit = false) {
    const label = implicit && state === 'completed' ? '已结束' : M.states[state] || state;
    const node = element('span', label, 'aw-state');
    node.dataset.state = state;
    return node;
  }
  function download(value, name) {
    const url = URL.createObjectURL(new Blob([json(value)], {type:'application/json;charset=utf-8'}));
    const link = element('a');
    link.href = url;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function mount(root, client, options = {}) {
    root.classList.add('adh-workbench', 'aw-history');
    root.innerHTML = `
      ${options.embedded ? '' : '<header class="aw-header"><h1>执行记录</h1><button type="button" id="awClose">返回分析现场</button></header>'}
      <section id="awNotice" class="aw-history-notice" role="alert" hidden>
        <p id="awNoticeText"></p><button type="button" id="awNoticeDismiss">关闭提示</button>
      </section>
      <section id="awListView">
        <div class="aw-history-heading">
          ${options.embedded ? '<h3>执行记录</h3>' : ''}
          <button type="button" id="awRefresh" class="aw-refresh">刷新</button>
        </div>
        <div class="aw-history-controls">
          <input id="awSearch" type="search" aria-label="搜索记录" placeholder="搜索记录">
          <select id="awState" aria-label="按状态筛选">
            <option value="">全部状态</option><option value="active">分析中</option>
            <option value="paused">已暂停</option><option value="unknown">结果未知</option>
            <option value="cancel_requested">取消中</option><option value="completed">已结束</option>
            <option value="cancelled">已取消</option>
          </select>
          <label class="aw-check"><input id="awShowSettingSaves" type="checkbox">显示设置修改</label>
        </div>
        <div id="awTaskList" class="aw-history-list" aria-live="polite">
          <p class="aw-history-empty">正在读取执行记录…</p>
        </div>
        <div class="aw-row aw-history-pages" id="awTaskPages" hidden>
          <button type="button" id="awTaskPrev">上一页</button><button type="button" id="awTaskNext">下一页</button>
        </div>
      </section>
      <section id="awDetailView" hidden>
        <button type="button" class="aw-back" id="awListBack">‹ 返回执行记录</button>
        <div id="awTaskHead" class="aw-task-heading"></div>
        <section id="awOperationsSection" hidden>
          <div id="awOperationRows" class="aw-history-list"></div>
          <div class="aw-row aw-history-pages" id="awOpPages" hidden>
            <button type="button" id="awOpPrev">上页操作</button><button type="button" id="awOpNext">下页操作</button>
          </div>
        </section>
        <article id="awOperationDetail" class="aw-detail-section" hidden></article>
      </section>`;
    const $ = id => root.querySelector('#' + id);
    const state = {
      visible:true, busy:false, refreshing:false, listOffset:0, opOffset:0,
      taskId:null, opId:null, savedResults:null, listGeneration:0, detailGeneration:0, operationGeneration:0,
    };
    let timer, searchTimer, lastListRender = '', lastTaskRender = '', lastRowsRender = '', lastOpRender = '';

    function report(error) {
      $('awNoticeText').textContent = error?.message || '读取执行记录失败';
      $('awNotice').hidden = false;
    }
    function permissions() {
      $('awRefresh').disabled = state.busy;
      for (const node of root.querySelectorAll('[data-navigate]')) node.disabled = state.busy;
    }
    async function work(fn) {
      if (state.busy) return;
      state.busy = true;
      $('awNotice').hidden = true;
      permissions();
      try { await fn(); }
      catch (error) { report(error); }
      finally { state.busy = false; permissions(); }
    }
    function formatMeta(record) {
      return [sources.get(record.source), M.time(record.updatedAt ?? record.createdAt)].filter(Boolean).join(' · ');
    }
    function entry(title, meta, status, select) {
      const row = button('', select, 'aw-history-row');
      row.dataset.navigate = '';
      const content = element('span', undefined, 'aw-history-content');
      content.append(element('span', title, 'aw-task-title'), element('span', meta, 'aw-task-meta'));
      row.append(content, status, element('span', '›', 'aw-chevron'));
      row.lastChild.setAttribute('aria-hidden', 'true');
      return row;
    }
    function setPaging(prefix, offset, next) {
      $(prefix + 'Pages').hidden = offset === 0 && next == null;
      $(prefix + 'Prev').disabled = offset === 0;
      $(prefix + 'Next').disabled = next == null;
    }
    function filter() {
      state.listOffset = 0;
      refreshList().catch(report);
    }
    $('awNoticeDismiss').onclick = () => { $('awNotice').hidden = true; };
    const close = $('awClose');
    if (close) close.onclick = () => options.close ? options.close() : location.assign('/');
    $('awSearch').oninput = () => { clearTimeout(searchTimer); searchTimer = setTimeout(filter, 250); };
    $('awState').onchange = filter;
    $('awShowSettingSaves').onchange = filter;
    $('awRefresh').onclick = () => work(refreshList);
    $('awTaskPrev').onclick = () => { state.listOffset = Math.max(0, state.listOffset - PAGE_SIZE); refreshList().catch(report); };
    $('awTaskNext').onclick = () => { state.listOffset += PAGE_SIZE; refreshList().catch(report); };
    $('awOpPrev').onclick = () => { state.opOffset = Math.max(0, state.opOffset - PAGE_SIZE); refreshTask().catch(report); };
    $('awOpNext').onclick = () => { state.opOffset += PAGE_SIZE; refreshTask().catch(report); };

    async function refreshList() {
      const generation = ++state.listGeneration;
      const query = $('awSearch').value.trim();
      const alias = [...titles].find(([, label]) => label === query)?.[0];
      const value = await client.management({
        action:'list', limit:PAGE_SIZE, offset:state.listOffset,
        q:alias || query, state:$('awState').value, hideSettingSaves:!$('awShowSettingSaves').checked,
      });
      if (generation !== state.listGeneration) return;
      setPaging('awTask', state.listOffset, value.nextTaskOffset);
      const signature = json(value.tasks);
      if (signature === lastListRender) return;
      lastListRender = signature;
      const rows = value.tasks.map(task => entry(titleFor(task.title), formatMeta(task), badge(task.state, task.implicit), () => work(() => selectTask(task.id))));
      if (!rows.length) rows.push(element('p', '没有符合条件的执行记录。', 'aw-history-empty'));
      $('awTaskList').replaceChildren(...rows);
      permissions();
    }
    $('awListBack').onclick = () => {
      state.taskId = null;
      state.opId = null;
      state.detailGeneration++;
      state.operationGeneration++;
      $('awDetailView').hidden = true;
      $('awListView').hidden = false;
      $('awSearch').focus({preventScroll:true});
      refreshList().catch(report);
    };

    async function selectTask(id, openSingle = true) {
      state.taskId = id;
      state.opId = null;
      state.opOffset = 0;
      state.savedResults = null;
      lastTaskRender = '';
      lastRowsRender = '';
      $('awListView').hidden = true;
      $('awDetailView').hidden = false;
      $('awTaskHead').replaceChildren(element('p', '正在读取结果…', 'aw-muted'));
      $('awOperationsSection').hidden = true;
      $('awOperationDetail').hidden = true;
      $('awListBack').focus({preventScroll:true});
      const value = await refreshTask();
      if (openSingle && value?.totalOperations === 1) await selectOperation(value.operations[0].id);
    }
    async function refreshTask() {
      if (!state.taskId) return;
      const id = state.taskId, generation = ++state.detailGeneration;
      const value = await client.management({action:'get', taskId:id, limit:PAGE_SIZE, offset:state.opOffset});
      if (id !== state.taskId || generation !== state.detailGeneration) return;
      const {task} = value;
      const signature = json([task.title, task.state, task.updatedAt]);
      if (signature !== lastTaskRender) {
        lastTaskRender = signature;
        const heading = element('div', undefined, 'aw-row');
        heading.append(element('h2', titleFor(task.title)), badge(task.state, task.implicit));
        $('awTaskHead').replaceChildren(heading, element('p', formatMeta(task), 'aw-muted'));
      }
      $('awOperationsSection').hidden = false;
      setPaging('awOp', state.opOffset, value.nextOperationOffset);
      const rowsSignature = json(value.operations) + '|' + state.opId;
      if (rowsSignature !== lastRowsRender) {
        lastRowsRender = rowsSignature;
        const rows = value.operations.map(op => {
          const row = entry(titleFor(op.name), M.time(op.finishedAt ?? op.createdAt), badge(op.state), () => work(() => selectOperation(op.id)));
          row.dataset.operation = op.id;
          row.setAttribute('aria-pressed', String(op.id === state.opId));
          return row;
        });
        if (!rows.length) rows.push(element('p', '这项记录还没有执行结果。', 'aw-history-empty'));
        $('awOperationRows').replaceChildren(...rows);
      }
      permissions();
      if (state.opId) await refreshOperation();
      return value;
    }
    async function goOperation(id) {
      const {operation} = await client.management({action:'get', id});
      if (state.taskId !== operation.taskId) await selectTask(operation.taskId, false);
      await selectOperation(id);
    }
    async function selectOperation(id) {
      state.opId = id;
      state.savedResults = null;
      lastOpRender = '';
      for (const row of $('awOperationRows').querySelectorAll('[data-operation]')) {
        row.setAttribute('aria-pressed', String(row.dataset.operation === id));
      }
      $('awOperationDetail').hidden = true;
      await refreshOperation();
    }
    const resultSignature = operation => json([operation.resultFile, operation.lateResultFile]);
    async function refreshOperation() {
      const id = state.opId, generation = ++state.operationGeneration;
      const current = () => id === state.opId && generation === state.operationGeneration;
      let includeResult = state.savedResults === null;
      let {operation} = await client.management({action:'get', id, includeResult});
      if (!current()) return;
      if (!includeResult && resultSignature(operation) !== state.savedResults.signature) {
        includeResult = true;
        ({operation} = await client.management({action:'get', id, includeResult}));
        if (!current()) return;
      }
      if (includeResult) {
        state.savedResults = {signature:resultSignature(operation), result:operation.result, lateResult:operation.lateResult};
      }
      const signature = json([id, operation.state, operation.error?.message, state.savedResults.signature]);
      if (signature !== lastOpRender) {
        lastOpRender = signature;
        renderOperation(operation);
      }
    }
    function renderOperation(op) {
      const area = $('awOperationDetail');
      area.hidden = false;
      const heading = element('div', undefined, 'aw-row');
      heading.append(element('h3', '执行结果'), badge(op.state));
      area.replaceChildren(heading);
      if (op.error?.message) area.append(element('p', op.error.message, 'aw-history-empty'));
      if (state.savedResults.result === undefined && state.savedResults.lateResult === undefined && !op.error?.message) {
        area.append(element('p', '还没有可查看的结果。', 'aw-history-empty'));
      }
      for (const [key, label] of [['result', '原始结果'], ['lateResult', '晚到结果']]) {
        const value = state.savedResults[key];
        if (value === undefined) continue;
        const payload = value?.body ?? value;
        const message = [payload?.summary, payload?.message, payload?.note, payload?.error]
          .find(text => typeof text === 'string' && text.length <= 300 && text.trim());
        if (message) area.append(element('p', message, 'aw-result-summary'));
        const details = element('details', undefined, 'aw-result-block');
        const raw = json(value);
        details.append(element('summary', label), element('pre', raw.length > 120000 ? raw.slice(0, 120000) + '\n…界面预览已截断' : raw));
        if (value?.omitted) details.append(element('p', '仅保存了结果摘要。'));
        details.append(button('下载' + label, () => download(value, op.id + '-' + key + '.json')));
        area.append(details);
      }
    }
    async function refresh() {
      if (state.taskId) await refreshTask();
      else await refreshList();
    }
    function start() {
      state.visible = true;
      if (timer) return;
      timer = setInterval(() => {
        if (!state.visible || document.hidden || state.busy || state.refreshing) return;
        if (root.contains(document.activeElement) && document.activeElement?.matches('input,textarea,select')) return;
        state.refreshing = true;
        refresh().catch(report).finally(() => state.refreshing = false);
      }, 5000);
    }
    start();
    refresh().catch(report);
    if (options.standalone) {
      const params = new URLSearchParams(location.search);
      if (params.get('operation')) work(() => goOperation(params.get('operation')));
      else if (params.get('task')) work(() => selectTask(params.get('task')));
    }
    return {
      open() { start(); refresh().catch(report); },
      pause() { state.visible = false; clearInterval(timer); clearTimeout(searchTimer); timer = undefined; },
      refresh,
    };
  }
  scope.AdhWorkbench = {mount};
})(globalThis);
