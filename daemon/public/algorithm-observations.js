// Classify algorithm labels already loaded by the panel. Observation rows never carry payloads.
((scope) => {
  const families = Object.freeze({
    digest:'摘要', mac:'消息认证', symmetric:'对称加密', asymmetric:'非对称与签名',
    aead:'AEAD', tls:'传输加密', kdf:'密钥派生', agreement:'密钥协商', random:'随机数', other:'其他',
  });
  const rules = [
    ['kdf','PBKDF2',/PBKDF2/], ['kdf','HKDF',/HKDF/], ['kdf','scrypt',/SCRYPT/],
    ['kdf','Argon2',/ARGON2/], ['kdf','密钥派生',/^(?:KDF|密钥派生)$/],
    ['agreement','X25519',/X25519/], ['agreement','X448',/X448/], ['agreement','ECDH',/ECDH/],
    ['agreement','密钥协商',/^DH$|DIFFIEHELLMAN|密钥协商/],
    ['random','随机数',/SECURERANDOM|CSPRNG|^(?:RNG|RANDOM)$|随机数/],
    ['tls','TLS',/^(?:TLS|SSL)/],
    ['aead','ChaCha20-Poly1305',/CHACHA20POLY1305/], ['aead','AES-GCM',/AES(?:128|192|256)?GCM/],
    ['aead','AES-CCM',/AES(?:128|192|256)?CCM/], ['aead','AEAD',/AEAD|^GCM$|^CCM$/],
    ['mac','HMAC',/HMAC/], ['mac','CMAC',/CMAC/], ['mac','Poly1305',/POLY1305/],
    ['asymmetric','Ed25519',/ED25519/], ['asymmetric','ECDSA',/ECDSA/], ['asymmetric','RSA',/RSA/],
    ['asymmetric','DSA',/^DSA/], ['asymmetric','签名与验签',/签名|验签|非对称/],
    ['digest','SHA-3',/SHA3(?:224|256|384|512)?$/],
    ['digest','SHA-512',/SHA512/], ['digest','SHA-384',/SHA384/], ['digest','SHA-256',/SHA256/],
    ['digest','SHA-224',/SHA224/], ['digest','SHA-1',/SHA1/], ['digest','MD5',/MD5/],
    ['digest','摘要',/^(?:SHA|DIGEST)$|摘要/],
    ['symmetric','AES',/AES/], ['symmetric','ChaCha20',/CHACHA20/], ['symmetric','SM4',/SM4/],
    ['symmetric','DES',/^(?:(?:TRIPLE)?DES|3DES)(?:CBC|ECB)?$/], ['symmetric','对称加密',/对称/],
  ];

  function identify(record) {
    const tag = typeof record?.algo === 'string' ? record.algo.slice(0, 96).replace(/[\s_/-]+/g, '').toUpperCase() : '';
    if (record?.category === 'net') return /^(?:TLS|SSL)/.test(tag) ? ['tls','TLS'] : undefined;
    if (record?.category !== 'crypto') return;
    const match = rules.find(([, , pattern]) => pattern.test(tag));
    return match ? [match[0], match[1]] : ['other','未识别算法'];
  }

  function summarize(records) {
    const counts = new Map();
    for (const record of records) {
      const type = identify(record);
      if (!type) continue;
      const [family, name] = type;
      const key = family + ':' + name;
      const previous = counts.get(key);
      const ts = Number.isFinite(record.ts) && record.ts > 0 ? record.ts : 0;
      counts.set(key, {
        family, name, count:(previous?.count ?? 0) + 1, latest:Math.max(previous?.latest ?? 0, ts),
      });
    }
    return [...counts.values()].sort((a,b) => b.latest - a.latest || b.count - a.count || a.name.localeCompare(b.name));
  }

  scope.AdhAlgorithmObservations = {families, summarize};
})(globalThis);
