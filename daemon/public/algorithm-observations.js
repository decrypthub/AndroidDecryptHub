// Summaries and display preferences for loaded observations. Never read capture payloads.
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
    // Legacy family labels can list possibilities, not the algorithm that actually ran.
    if (/^RSAEC(?:签名|验签)$/.test(tag)) return ['asymmetric','签名与验签'];
    if (/^AEAD(?:加密|解密)\(/.test(tag)) return ['aead','AEAD'];
    const hmac = /^HMAC(?:WITH)?(SHA3(?:224|256|384|512)|SHA(?:1|224|256|384|512)|MD5)$/.exec(tag);
    if (hmac) {
      const hash = hmac[1].replace(/^SHA3(\d{3})$/, 'SHA-3-$1').replace(/^SHA(\d+)$/, 'SHA-$1');
      return ['mac','HMAC-'+hash];
    }
    const sha3 = /^SHA3(224|256|384|512)$/.exec(tag);
    if (sha3) return ['digest','SHA-3-'+sha3[1]];
    const aesMode = /^AES(?:128|192|256)?(CBC|CTR|CFB(?:8|128)?|OFB|ECB|XTS)(?:NOPADDING|PKCS[57]PADDING|ISO10126PADDING)?$/.exec(tag);
    if (aesMode) return ['symmetric','AES-'+aesMode[1]];
    const match = rules.find(([, , pattern]) => pattern.test(tag));
    return match ? [match[0], match[1]] : ['other','未识别算法'];
  }

  const algorithmKeyFor = ([family,name]) => 'algo:'+family+':'+name;
  function algorithmKey(record) {
    const type = identify(record);
    return type && algorithmKeyFor(type);
  }
  const timeOf = record => Number.isFinite(record.ts) && record.ts > 0 ? record.ts : 0;

  function summarize(records, hidden = new Set()) {
    const entries = new Map();
    for (const record of records) {
      const type = identify(record);
      if (!type) continue;
      const [family, name] = type;
      const key = algorithmKeyFor(type);
      if (!entries.has(key)) entries.set(key,{key,family,name,count:0,shown:0,latest:0,methods:new Map()});
      const entry = entries.get(key);
      const shown = !hidden.has(key) && !hidden.has(hookKey(record));
      entry.count++;
      if (shown) entry.shown++;
      entry.latest = Math.max(entry.latest,timeOf(record));
      const method = recordedMethod(record);
      const methodKey = JSON.stringify(method);
      const previous = entry.methods.get(methodKey);
      entry.methods.set(methodKey,{...method,count:(previous?.count ?? 0)+1});
    }
    return [...entries.values()]
      .map(entry => ({...entry,methods:[...entry.methods.values()].sort((a,b)=>
        a.className.localeCompare(b.className) || a.member.localeCompare(b.member) || a.label.localeCompare(b.label))}))
      .sort((a,b) => b.latest - a.latest || b.count - a.count || a.name.localeCompare(b.name));
  }

  const hookGroups = Object.freeze({crypto:'加解密', system:'系统', file:'文件', net:'网络'});
  const symbol = value => typeof value === 'string' && /^[\p{L}\p{N}_.$:@+<>-]{1,120}$/u.test(value) ? value : '';
  const sourceOf = record => record.source === 'java' || record.source === 'native' ? record.source : '';
  const javaIdentifier = /^[\p{L}_$][\p{L}\p{N}_$]*$/u;
  function recordedMethod(record) {
    const source = sourceOf(record);
    const name = symbol(record.func);
    if (source === 'native') return {source,className:'',member:name,label:''};
    if (source === 'java') {
      const parts = name.split('.');
      const tail = parts.pop();
      const valid = javaIdentifier.test(tail) || tail === '<init>' || tail === '<clinit>';
      if (valid && parts.length && parts.every(part=>javaIdentifier.test(part))) {
        return {source,className:parts.join('.'),member:tail,label:''};
      }
      // view.hook can be a UI alias derived from the operation, not a recorded class.
      const member = valid && !parts.length ? tail : '';
      const label = (name && !member ? name : '') || symbol(record.view?.hook);
      return {source,className:'',member,label:label===member?'':label};
    }
    return {source,className:'',member:'',label:name};
  }

  function hookIdentity(record) {
    const category = record?.category;
    if (!Object.hasOwn(hookGroups, category)) return;
    const name = symbol(record.func) || symbol(record.view?.hook);
    if (!name) return;
    const source = sourceOf(record);
    return {key:JSON.stringify([category,source,name]), category, source, name};
  }
  const hookKey = record => hookIdentity(record)?.key;
  const recordVisible = (record,hidden) => !hidden.has(hookKey(record)) && !hidden.has(algorithmKey(record));

  function summarizeHooks(records) {
    const items = new Map();
    for (const record of records) {
      const hook = hookIdentity(record);
      if (!hook) continue;
      const previous = items.get(hook.key);
      const ts = timeOf(record);
      items.set(hook.key, {...hook, count:(previous?.count ?? 0)+1, latest:Math.max(previous?.latest ?? 0, ts)});
    }
    return [...items.values()].sort((a,b) => a.name.localeCompare(b.name) || a.source.localeCompare(b.source));
  }

  function choiceGroups(items, labels, field, hidden, matches) {
    const groups = new Map(Object.entries(labels).map(([id,name]) => [id,{id,name,selected:0,total:0,items:[]}]));
    for (const item of items) {
      const group = groups.get(item[field]);
      if (!group) continue;
      group.total++;
      if (!hidden.has(item.key)) group.selected++;
      if (matches(item,group.name)) group.items.push(item);
    }
    return [...groups.values()].filter(group => group.items.length);
  }

  function hookDisplayPreferences(storage) {
    const keyFor = pkg => 'adh.panel.hidden-hooks.v1:' + pkg;
    const byPackage = new Map();
    return {
      hidden(pkg) {
        if (!pkg) return new Set();
        if (!byPackage.has(pkg)) {
          let saved = [];
          try { saved = JSON.parse(storage().getItem(keyFor(pkg))); } catch {}
          byPackage.set(pkg,new Set(Array.isArray(saved) ? saved.filter(key => typeof key === 'string' && key.length < 160) : []));
        }
        return byPackage.get(pkg);
      },
      save(pkg, hidden) {
        if (!pkg) return false;
        byPackage.set(pkg,new Set(hidden));
        try {
          if (hidden.size) storage().setItem(keyFor(pkg),JSON.stringify([...hidden]));
          else storage().removeItem(keyFor(pkg));
          return true;
        } catch { return false; }
      },
    };
  }

  scope.AdhAlgorithmObservations = {families, summarize, hookGroups, summarizeHooks, choiceGroups,
    algorithmKey, hookKey, recordVisible, hookDisplayPreferences};
})(globalThis);
