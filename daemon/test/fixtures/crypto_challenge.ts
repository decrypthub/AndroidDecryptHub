// Synthetic evidence producer, independent of the verifier. No target constants or captured data.
// The seed is deliberately not included in the evidence the verifier receives.
import { createHash, createHmac, randomBytes } from 'node:crypto';
import type { CryptoAlgorithm, CryptoEvidenceInput, CryptoObservation, EvidenceBytes, EvidenceSource } from '../../src/crypto_evidence.ts';

export function buildCryptoChallenge(seed = randomBytes(32).toString('hex'), rounds = 12) {
  if (!/^[0-9a-f]{64}$/i.test(seed)) throw new Error('seed must be 32 bytes of hex');
  if (!Number.isSafeInteger(rounds) || rounds < 4 || rounds > 16) throw new Error('rounds must be 4..16');
  const secretSeed = Buffer.from(seed, 'hex');
  let counter = 0, captureId = 1;
  const take = (label: string, size: number) => {
    const blocks: Buffer[] = [];
    while (Buffer.concat(blocks).length < size) blocks.push(createHmac('sha256', secretSeed).update(`${label}:${counter++}`).digest());
    return Buffer.concat(blocks).subarray(0, size);
  };
  const observations: CryptoObservation[] = [];
  const profileKeys = new Map<number, Buffer>();
  const validIds: string[] = [], mismatchedIds: string[] = [], unavailableIds: string[] = [];
  const bytes = (data: Buffer, source: EvidenceSource): EvidenceBytes => ({ hex: data.toString('hex'), expectedBytes: data.length, source });
  const session = 'synthetic-crypto-challenge';
  for (let round = 0; round < rounds; round++) {
    const recipe = round % 4, profile = Math.floor(round / 2), tid = 2000 + round;
    if (!profileKeys.has(profile)) profileKeys.set(profile, take(`key-profile-${profile}`, [0, 16, 36, 65, 96][profile % 5]));
    const key = profileKeys.get(profile)!;
    let current: Buffer = take(`message-${round}`, 31 + round * 7);
    // Force genuinely binary data: exact-byte joins must not use printable previews.
    current[0] = 0; current[1] = 0xff; current[2] = 0x0a;
    const firstInput = Buffer.from(current);
    const stages: CryptoAlgorithm[][] = [
      ['sha256', 'add-xor', 'hmac-sha1', 'xor', 'base64'],
      ['md5', 'xor', 'hmac-sha256', 'add-xor', 'hex-lower'],
      ['sha512', 'add-xor', 'hmac-md5', 'base64'],
      ['hmac-sha512', 'xor', 'sha256', 'hex-upper'],
    ];
    for (let stage = 0; stage < stages[recipe].length; stage++) {
      const algorithm = stages[recipe][stage], id = `r${round}:s${stage}:${algorithm}`;
      const source: EvidenceSource = { kind: 'hook-window', session, pid: 4000, tid, hookId: 10 + stage, seq: round + 1 };
      const inputSource = { ...source, captureId: captureId++, phase: 'before', slot: 'input' };
      const input = Buffer.from(current);
      const parameters: CryptoObservation['params'] = {};
      const parameterSource: EvidenceSource = { kind: 'capture', session, tid: 99, captureId: captureId++, slot: `initialization-profile-${profile}` };
      let output: Buffer;
      if (algorithm === 'add-xor' || algorithm === 'xor') {
        const add = take(`add-${profile}-${stage}`, input.length), xor = take(`xor-${profile}-${stage}`, input.length);
        if (algorithm === 'add-xor') parameters.add = bytes(add, { ...parameterSource, slot: 'add-mask' });
        parameters.xor = bytes(xor, { ...parameterSource, slot: 'xor-mask' });
        // A different implementation from the verifier's scalar loop.
        output = Buffer.from([...input].map((value, i) => ((algorithm === 'add-xor' ? value + add[i] : value) % 256) ^ xor[i]));
      } else if (algorithm.startsWith('hmac-')) output = createHmac(algorithm.substring(5), key).update(input).digest();
      else if (algorithm === 'hex-lower' || algorithm === 'hex-upper') {
        const text = input.toString('hex'); output = Buffer.from(algorithm === 'hex-upper' ? text.toUpperCase() : text);
      } else if (algorithm === 'base64') output = Buffer.from(input.toString('base64'));
      else output = createHash(algorithm).update(input).digest();
      const split = Math.floor(input.length / 3);
      observations.push({ id, algorithms: [algorithm], role: stage + 1 === stages[recipe].length ? 'final' : 'intermediate',
        parameterLabel: 'caller-reuses-label',
        input: [bytes(input.subarray(0, split), inputSource), bytes(input.subarray(split, split * 2), inputSource), bytes(input.subarray(split * 2), inputSource)],
        output: bytes(output, { ...source, captureId: captureId++, phase: 'after', slot: 'output' }),
        ...(algorithm.startsWith('hmac-') ? { key: bytes(key, { ...parameterSource, slot: 'key' }) } : {}),
        ...(algorithm === 'xor' || algorithm === 'add-xor' ? { params: parameters } : {}) });
      validIds.push(id); current = output;
    }
    if (round === 0) {
      const src = { kind: 'oracle' as const, session, callId: 'wrong-whole-chain-claim', tid };
      observations.push({ id: 'negative:intermediate-is-not-final', role: 'final', algorithms: ['sha256'],
        input: bytes(firstInput, src), output: bytes(current, src) });
      mismatchedIds.push('negative:intermediate-is-not-final');
    }
  }
  const valid = observations[2], inputPart = valid.input as EvidenceBytes[];
  const crossThread: CryptoObservation = structuredClone(valid);
  crossThread.id = 'negative:cross-thread'; crossThread.output!.source.tid = 9999;
  observations.push(crossThread); unavailableIds.push(crossThread.id);
  const crossHook = structuredClone(valid); crossHook.id = 'negative:cross-hook-same-seq'; crossHook.output!.source.hookId = 999;
  observations.push(crossHook); unavailableIds.push(crossHook.id);
  const short = structuredClone(valid); short.id = 'negative:truncated'; short.output!.hex = short.output!.hex!.slice(0, -2);
  observations.push(short); unavailableIds.push(short.id);
  const missing = structuredClone(valid); missing.id = 'negative:missing-output'; delete missing.output;
  observations.push(missing); unavailableIds.push(missing.id);
  const corrupt = structuredClone(valid); corrupt.id = 'negative:wrong-parameter';
  corrupt.key!.hex = Buffer.from('an unrelated captured key').toString('hex'); corrupt.key!.expectedBytes = corrupt.key!.hex.length / 2;
  observations.push(corrupt); mismatchedIds.push(corrupt.id);
  // Same tid and identical time would not rescue this pair: no recorded invocation identity.
  const noInvocation = structuredClone(valid); noInvocation.id = 'negative:thread-alone';
  for (const b of [...noInvocation.input as EvidenceBytes[], noInvocation.output!]) {
    delete b.source.hookId; delete b.source.seq; delete b.source.captureId;
  }
  observations.push(noInvocation); unavailableIds.push(noInvocation.id);
  const staleOutput = structuredClone(valid); staleOutput.id = 'negative:stale-output'; staleOutput.output!.source.seq!--;
  observations.push(staleOutput); unavailableIds.push(staleOutput.id);
  // Permute records deterministically: the verifier must not rely on array adjacency or call order.
  observations.sort((a, b) => createHash('sha256').update(seed + a.id).digest('hex').localeCompare(createHash('sha256').update(seed + b.id).digest('hex')));
  const input: CryptoEvidenceInput = { observations, loss: { complete: true, dropped: 0 } };
  return { seed, input, expected: { validIds, mismatchedIds, unavailableIds,
    recipes: 4, parameterProfiles: Math.ceil(rounds / 2), binaryChunkedInputs: validIds.length, sourceInputBytes: inputPart.reduce((n, b) => n + b.expectedBytes!, 0) } };
}
