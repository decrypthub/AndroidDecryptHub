import test from 'node:test';
import assert from 'node:assert/strict';

import { ingestAgentCaptureFrame } from '../src/service.ts';
import { capStats, captures, sessions } from '../src/state.ts';

test('agent-pushed captureBatch ingests native and Java records with sender accounting', () => {
  const sid = 'capture-batch-fixture';
  const saved = captures.slice();
  captures.length = 0; capStats.delete(sid);
  sessions.set(sid, { sessionId: sid, online: true, package: '?', process: '?', pid: 1, uid: 10001, starttimeTicks: '1' } as any);

  try {
    ingestAgentCaptureFrame(sid, {
      t: 'captureBatch', count: 2, jcount: 1, seq: 2, drained: 2,
      dropped: 0, jdropped: 0, backlog: 3, queued: 1, complete: true, ring: 2048,
      captures: [
        { func: 'EVP_CipherUpdate', inl: 2, tid: 11, tsNs: 101, hex: '6162', key: '30', iv: '31' },
        { func: 'read', inl: 1, tid: 12, tsNs: 102, hex: '63', path: '/data/local/tmp/x' },
      ],
      jcaptures: [
        { algo: 'AES/CBC/PKCS5Padding', op: 'Cipher.doFinal', inl: 2, outl: 2, tid: 13, tsNs: 103, in: '6465', out: '6667', key: '38', iv: '39' },
      ],
    });

    const stats = capStats.get(sid);
    assert.equal(stats?.seq, 2);
    assert.equal(stats?.emitted, 2);
    assert.equal(stats?.drained, 2);
    assert.equal(stats?.backlog, 3);
    assert.equal(stats?.queued, 1);
    assert.equal(stats?.complete, true);
    assert.equal(captures.length, 3);
    assert.equal(captures[0].source, 'java');
    assert.equal(captures[0].keyHex, '38');
    assert.equal(captures[1].func, 'EVP_CipherUpdate');
    assert.equal(captures[1].keyHex, '30');
    assert.equal(captures[2].category, 'file');
    assert.equal(captures[2].path, '/data/local/tmp/x');
  } finally {
    sessions.delete(sid); capStats.delete(sid);
    captures.length = 0;
    for (const capture of saved) captures.push(capture);
  }
});

test('out-of-order capture frames merge health without losing emitted records', () => {
  const sid = 'capture-batch-order-fixture';
  const saved = captures.slice();
  captures.length = 0; capStats.delete(sid);
  sessions.set(sid, { sessionId: sid, online: true, package: '?', process: '?', pid: 1, uid: 10001, starttimeTicks: '1' } as any);

  try {
    // A drain popped after the sender's batch but reached the daemon first: the two pushed
    // records are still represented by queued/backlog in this newer snapshot.
    ingestAgentCaptureFrame(sid, {
      t: 'cmdResult', op: 'capture_drain', count: 1, frameSeq: 2, seq: 3, drained: 1,
      dropped: 0, jdropped: 0, backlog: 2, queued: 2, queuedSeq: 1, complete: true, ring: 128,
      captures: [{ func: 'read', inl: 1, tid: 1, tsNs: 2, hex: '62' }],
      jcaptures: [],
    });
    // The older pushed batch arrives late. It must still be stored and counted, while its two
    // records move out of queued/backlog in the newer health snapshot.
    ingestAgentCaptureFrame(sid, {
      t: 'captureBatch', count: 2, frameSeq: 1, seq: 3, drained: 2,
      dropped: 0, jdropped: 0, backlog: 1, queued: 0, complete: true, ring: 128,
      captures: [
        { func: 'read', inl: 1, tid: 1, tsNs: 0, hex: '61' },
        { func: 'read', inl: 1, tid: 1, tsNs: 1, hex: '63' },
      ],
      jcaptures: [],
    });

    let stats = capStats.get(sid);
    assert.equal(stats?.seq, 3);
    assert.equal(stats?.emitted, 3);
    assert.equal(stats?.drained, 3);
    assert.equal(stats?.backlog, 0);
    assert.equal(stats?.queued, 0);
    assert.equal(stats?.frameSeq, 2);
    assert.equal(captures.length, 3);

    captures.length = 0; capStats.delete(sid);
    // The symmetric case: a pushed batch reached the daemon before a drain reply whose snapshot
    // still queued it. queuedSeq tells the host that queued work is already delivered, so the
    // drain settles it into drained instead of reviving backlog.
    ingestAgentCaptureFrame(sid, {
      t: 'captureBatch', count: 2, frameSeq: 2, seq: 3, drained: 3,
      dropped: 0, jdropped: 0, backlog: 0, queued: 0, complete: true, ring: 128,
      captures: [
        { func: 'read', inl: 1, tid: 1, tsNs: 1, hex: '62' },
        { func: 'read', inl: 1, tid: 1, tsNs: 2, hex: '63' },
      ],
      jcaptures: [],
    });
    ingestAgentCaptureFrame(sid, {
      t: 'cmdResult', op: 'capture_drain', count: 1, frameSeq: 1, seq: 1, drained: 1,
      dropped: 0, jdropped: 0, backlog: 2, queued: 2, queuedSeq: 2, complete: true, ring: 128,
      captures: [{ func: 'read', inl: 1, tid: 1, tsNs: 0, hex: '61' }],
      jcaptures: [],
    });

    stats = capStats.get(sid);
    assert.equal(stats?.seq, 3);
    assert.equal(stats?.emitted, 3);
    assert.equal(stats?.drained, 3);
    assert.equal(stats?.backlog, 0);
    assert.equal(captures.length, 3);
  } finally {
    sessions.delete(sid); capStats.delete(sid);
    captures.length = 0;
    for (const capture of saved) captures.push(capture);
  }
});
