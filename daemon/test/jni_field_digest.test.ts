import test from 'node:test';
import assert from 'node:assert/strict';
import { digestJniFields } from '../src/jni_field_digest.ts';

const idEvent = (value) => ({ function: 'GetFieldID', value, ok: true, ts: 1, tid: 7 });
const access = (fn, value, ts = 2, tid = 7) => ({ function: fn, value, ok: true, ts, tid });

test('an access is joined to the field name its jfieldID was handed out with', () => {
  const d = digestJniFields([
    idEvent('com.example.Foo#isDebug:Z -> 0xAAAA'),
    access('GetBooleanField', 'field=0xaaaa value=0'),
    access('SetBooleanField', 'field=0xAAAA value=1', 3),
  ]);
  assert.equal(d.samples, 2);
  assert.equal(d.idEvents, 1);
  assert.equal(d.resolvedIds, 1);
  assert.equal(d.unresolvedAccesses, 0);
  const set = d.groups.find((g) => g.accessor === 'SetBooleanField');
  assert.equal(set.field, 'com.example.Foo#isDebug:Z');
  assert.equal(set.resolved, true);
  assert.equal(set.lastValue, '1');
  assert.deepEqual(set.tids, [7]);
});

test('an access whose id was never seen stays an opaque pointer instead of guessing a name', () => {
  const d = digestJniFields([access('GetIntField', 'field=0xBEEF value=42')]);
  assert.equal(d.samples, 1);
  assert.equal(d.unresolvedAccesses, 1);
  assert.equal(d.groups[0].resolved, false);
  assert.equal(d.groups[0].field, '0xBEEF');
  assert.match(d.notes.join(' '), /could not be attributed/);
});

test('groups are per (accessor, field) and sorted by count', () => {
  const events = [idEvent('C#b:I -> 0x1'), idEvent('C#a:I -> 0x2')];
  for (let i = 0; i < 3; i++) events.push(access('GetIntField', 'field=0x1 value=' + i));
  events.push(access('GetIntField', 'field=0x2 value=9'));
  const d = digestJniFields(events);
  assert.equal(d.groups.length, 2);
  assert.equal(d.groups[0].field, 'C#b:I');
  assert.equal(d.groups[0].count, 3);
  assert.equal(d.groups[0].lastValue, '2');
  assert.equal(d.groups[1].field, 'C#a:I');
});

test('nothing to digest says so instead of looking like a clean result', () => {
  const d = digestJniFields([]);
  assert.equal(d.samples, 0);
  assert.match(d.notes.join(' '), /no JNIEnv field-access event/);
});

test('only real accessor names count: other JNI_ENV events are ignored', () => {
  const d = digestJniFields([
    { function: 'FindClass', value: 'com.example.Foo', ok: true },
    { function: 'GetFieldID', value: 'C#x:I -> 0x3', ok: true },
    { function: 'GetIntField', value: 'field=0x3 value=5', ok: true },
  ]);
  assert.equal(d.samples, 1);
  assert.equal(d.idEvents, 1);
});

test('a write whose stored value differs from what the target asked is reported as rewritten', () => {
  const d = digestJniFields([
    idEvent('com.example.Foo#isRooted:Z -> 0xAAAA'),
    access('SetBooleanField', 'field=0xAAAA value=0 requested=1'),
    access('SetBooleanField', 'field=0xAAAA value=0', 3),   // a normal write, not rewritten
  ]);
  assert.equal(d.rewrittenSamples, 1);
  const g = d.groups.find((x) => x.accessor === 'SetBooleanField');
  assert.equal(g.rewritten, 1);
  assert.equal(g.lastRequested, '1');
  assert.equal(g.lastValue, '0');       // the APPLIED value is what the target ended up storing
  assert.match(d.notes.join(' '), /REWRITTEN by an active setValue override/);
});

test('without an override nothing is reported as rewritten', () => {
  const d = digestJniFields([access('SetIntField', 'field=0xBEEF value=9')]);
  assert.equal(d.rewrittenSamples, 0);
  assert.equal(d.groups[0].rewritten, 0);
  assert.equal(d.groups[0].lastRequested, null);
  assert.doesNotMatch(d.notes.join(' '), /REWRITTEN/);
});
