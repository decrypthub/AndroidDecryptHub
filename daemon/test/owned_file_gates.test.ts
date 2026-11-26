import assert from 'node:assert/strict';
import test from 'node:test';
import {
  acceptsLocalHello, allowedOwnedRoot, allowedOwnedSave, usesDemoExternal,
  OWN_FILE_DEMO_NOTE, OWN_FILE_DEMO_PACKAGE, type LocalObserver,
} from '../src/local_observer.ts';

// files-only 观察：USB 自有目录、主用户（externalUser=0）、只允许写回一个声明过的文本名。
const filesOnly: LocalObserver = {
  package: 'com.example.debug', pid: 0, model: 'test', usbSerial: 'usb-1', ownFilesSerial: 'usb-1',
  fileBrowserOnly: true, externalUser: 0, editableText: 'adh-browser-proof.txt',
};
const hello = { t: 'hello', package: filesOnly.package, pid: 12, entry: 'jni_onload' };

test('files-only 模式不接受 Agent 连接', () => {
  assert.equal(acceptsLocalHello(filesOnly, hello), false);
  // 同一份 observer 关掉 files-only 才是 Agent 观察；否则本机文件入口会顺带被注入连接打开
  assert.equal(acceptsLocalHello({ ...filesOnly, fileBrowserOnly: false }, hello), true);
});

test('文件页面只允许声明过的根，且必须有 USB 自有目录', () => {
  assert.equal(allowedOwnedRoot(filesOnly, 'app'), true);
  assert.equal(allowedOwnedRoot(filesOnly, 'external'), true);
  assert.equal(allowedOwnedRoot(filesOnly, 'files'), false);
  assert.equal(allowedOwnedRoot(filesOnly, 'device'), false);
  // 主用户之外不放开原应用数据
  assert.equal(allowedOwnedRoot({ ...filesOnly, externalUser: 10 }, 'external'), false);
  // 非 files-only 的 Agent 观察只认 files 根
  const agent = { ...filesOnly, fileBrowserOnly: false };
  assert.equal(allowedOwnedRoot(agent, 'files'), true);
  assert.equal(allowedOwnedRoot(agent, 'app'), false);
  // 没有声明自有目录时任何根都不成立
  assert.equal(allowedOwnedRoot({ ...filesOnly, ownFilesSerial: undefined }, 'app'), false);
  assert.equal(allowedOwnedRoot({ ...filesOnly, ownFilesSerial: undefined }, 'external'), false);
});

test('保存只认声明过的那一个文本名，其余路径一律拒绝', () => {
  assert.equal(allowedOwnedSave(filesOnly, 'app', 'files/adh-browser-proof.txt'), true);
  for (const path of [
    'files/other.txt', 'files/../adh-browser-proof.txt', 'adh-browser-proof.txt',
    'files/sub/adh-browser-proof.txt', 'files/adh-browser-proof.txt/../other.txt',
  ]) {
    assert.equal(allowedOwnedSave(filesOnly, 'app', path), false);
  }
  // 外部根的那条豁免只给 Demo 隔离构建，普通 APK 不能借它写文件
  assert.equal(allowedOwnedSave(filesOnly, 'external', OWN_FILE_DEMO_NOTE), false);
  // 没声明可编辑文本时 app 根也不可写
  assert.equal(allowedOwnedSave({ ...filesOnly, editableText: undefined }, 'app', 'files/adh-browser-proof.txt'), false);
});

test('外部 Demo 备注只对 fileLab 隔离构建且显式开启可编辑时放行', () => {
  const filelab: LocalObserver = {
    ...filesOnly, package: OWN_FILE_DEMO_PACKAGE, demoExternal: true, demoExternalEdit: true,
  };
  assert.equal(usesDemoExternal(filelab, 'external'), true);
  assert.equal(allowedOwnedSave(filelab, 'external', OWN_FILE_DEMO_NOTE), true);
  for (const path of ['other.txt', '目录/' + OWN_FILE_DEMO_NOTE, '../' + OWN_FILE_DEMO_NOTE]) {
    assert.equal(allowedOwnedSave(filelab, 'external', path), false);
  }
  // 备注只能写进 external 根，不能顺带写原应用数据
  assert.equal(allowedOwnedSave(filelab, 'app', OWN_FILE_DEMO_NOTE), false);
  // 关掉任一前提（可编辑开关、外部目录开关、files-only、主用户、Demo 包名、USB 声明）都不再放行
  assert.equal(allowedOwnedSave({ ...filelab, demoExternalEdit: false }, 'external', OWN_FILE_DEMO_NOTE), false);
  for (const change of [
    { demoExternal: false }, { fileBrowserOnly: false }, { externalUser: 1 },
    { package: 'com.adh.sandbox' }, { ownFilesSerial: undefined },
  ]) {
    assert.equal(usesDemoExternal({ ...filelab, ...change }, 'external'), false);
  }
});
