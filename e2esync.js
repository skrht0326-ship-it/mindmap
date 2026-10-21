// 端末の中で暗号化してから Apps Script と同期する共通部品（マンダラ・マインドマップ共通）
// サーバーに届くのは「記録ID・更新時刻・暗号文」だけで、中身は管理者にも読めない。
//   招待コード  : PREFIX + base64({u: 同期URL, k: 合言葉})          … 許可リストから配る。鍵なし
//   端末用コード: PREFIX + base64({u: 同期URL, k: 合言葉, e: 鍵})   … 最初の端末で作る。2台目以降はこれを貼る
(function (g) {
  'use strict';
  var enc = new TextEncoder(), dec = new TextDecoder();
  function b64(buf) { var s = '', a = new Uint8Array(buf); for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function unb64(s) { var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function okUrl(u) { return /^https:\/\/script\.google(usercontent)?\.com\//.test(u) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(u); }
  function fail(code) { var e = new Error(code); e.code = code; return e; }

  function encodeCode(prefix, c) {
    var o = { u: c.u, k: c.k };
    if (c.e) o.e = c.e;
    return prefix + btoa(unescape(encodeURIComponent(JSON.stringify(o))));
  }
  function decodeCode(prefix, s) {
    s = (s || '').trim().replace(/\s+/g, '');
    if (s.indexOf(prefix) !== 0) return null;
    try {
      var o = JSON.parse(decodeURIComponent(escape(atob(s.slice(prefix.length)))));
      if (!o || !okUrl(o.u) || typeof o.k !== 'string' || !o.k) return null;
      var c = { u: o.u, k: o.k };
      if (typeof o.e === 'string' && unb64(o.e).length === 32) c.e = o.e;
      return c;
    } catch (e) { return null; }
  }

  var keys = {};
  function importKey(e) {
    if (!keys[e]) keys[e] = crypto.subtle.importKey('raw', unb64(e), 'AES-GCM', false, ['encrypt', 'decrypt']);
    return keys[e];
  }
  // 記録IDを追加認証データにして、別の記録と入れ替えられても気づけるようにする
  function seal(key, id, data) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(id) }, key, enc.encode(JSON.stringify(data)))
      .then(function (ct) { return { iv: b64(iv), ct: b64(ct) }; });
  }
  function open(key, id, r) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(r.iv), additionalData: enc.encode(id) }, key, unb64(r.ct))
      .then(function (pt) { return JSON.parse(dec.decode(pt)); });
  }

  function post(conf, body) {
    body.token = conf.k;
    return fetch(conf.u, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify(body), redirect: 'follow' })
      .then(function (r) { return r.json().catch(function () { throw fail('server'); }); }, function () { throw fail('network'); })
      .then(function (j) { if (!j || !j.ok) throw fail((j && j.error) || 'server'); return j; });
  }

  // recs: [{id, u, data}] を暗号化して送り、サーバーで since より後に変わった記録を復号して返す
  function exchange(conf, since, recs) {
    if (!conf || !conf.e) return Promise.reject(fail('no_key'));
    return importKey(conf.e).then(function (key) {
      return Promise.all(recs.map(function (r) {
        return seal(key, r.id, r.data).then(function (s) { return { id: r.id, u: r.u, iv: s.iv, ct: s.ct }; });
      })).then(function (out) {
        return post(conf, { since: since || 0, recs: out });
      }).then(function (j) {
        var list = j.recs || [];
        return Promise.all(list.map(function (r) {
          return open(key, r.id, r).then(function (d) { return { id: r.id, u: +r.u || 0, data: d }; }, function () { return null; });
        })).then(function (got) {
          // 1件でも読めなければ鍵が違う。rev を進めずに止める
          if (got.some(function (x) { return !x; })) throw fail('bad_key');
          return { rev: +j.rev || 0, recs: got };
        });
      });
    });
  }

  // 接続：鍵入りの端末用コードなら鍵が合うかを確かめる。鍵なしの招待コードは、空の保管場所に限り新しい鍵を作る
  function connect(prefix, s) {
    var c = decodeCode(prefix, s);
    if (!c) return Promise.reject(fail('bad_code'));
    if (c.e) return exchange(c, 0, []).then(function () { return c; });
    return post(c, { since: 0, recs: [] }).then(function (j) {
      if ((j.recs || []).length) throw fail('need_key');
      c.e = b64(crypto.getRandomValues(new Uint8Array(32)));
      return exchange(c, 0, [{ id: '_kc', u: Date.now(), data: { kc: 1 } }]).then(function () { return c; });
    });
  }

  var MSG = {
    bad_code: '接続コードを読み取れませんでした。コードをすべて貼り付けてください。',
    bad_token: '接続コードが使えません。許可が取り消されたか、コードが古い可能性があります。',
    need_key: 'この保管場所にはすでにデータがあります。最初に接続した端末で「端末用の接続コードを表示」を押し、そのコードを貼ってください。',
    bad_key: '暗号の鍵が一致しません。最初に接続した端末の「端末用の接続コード」を貼り直してください。',
    network: '同期先につながりませんでした。インターネット接続を確認してください。',
    server: '同期サーバーが応答しませんでした。少し待ってから試してください。'
  };
  function message(code) { return MSG[code] || MSG.server; }

  g.E2ESync = { encodeCode: encodeCode, decodeCode: decodeCode, exchange: exchange, connect: connect, message: message };
})(window);
