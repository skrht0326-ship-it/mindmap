// 端末の中で暗号化してから Apps Script と同期する共通部品（マンダラ・マインドマップ共通）
// サーバーに届くのは「でたらめな記録名・更新時刻・暗号文」と「端末ID」だけで、中身も項目の位置も管理者には読めない。
//   招待コード  : XXXX-XXXX（許可リストから配る。鍵なし）… 1台目に入れる
//   同期用リンク: アプリのURL#c=PREFIX+base64({u: 同期URL, k: 合言葉, e: 鍵})… 2台目以降で開く（貼っても可）
// 使い方：var S = E2ESync.create({ prefix: 'MANDALA2:', url: '<同期サーバーのURL>' });
(function (g) {
  'use strict';
  var enc = new TextEncoder(), dec = new TextDecoder();
  var ALPHA = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  function b64(buf) { var s = '', a = new Uint8Array(buf); for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function unb64(s) { var bin = atob(s), a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }
  function b64url(buf) { return b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function okUrl(u) { return /^https:\/\/script\.google(usercontent)?\.com\//.test(u) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(u); }
  function fail(code) { var e = new Error(code); e.code = code; return e; }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* 保存できなくても続ける */ } }

  // 招待コードの形（英数字8文字、ハイフン・空白・大小文字は問わない）
  function normInvite(s) {
    var t = String(s || '').toUpperCase().replace(/[^0-9A-Z]/g, '');
    if (t.length !== 8) return '';
    for (var i = 0; i < 8; i++) if (ALPHA.indexOf(t[i]) < 0) return '';
    return t.slice(0, 4) + '-' + t.slice(4);
  }

  function create(cfg) {
    var prefix = cfg.prefix, url = cfg.url;
    var DEV_KEY = 'e2e-dev-' + prefix.replace(/[^A-Z0-9]/gi, '');

    // この端末のID（台数の数え方に使う。中身とは関係ない乱数）
    function devId() {
      var d = lsGet(DEV_KEY);
      if (!d || d.length < 16) { d = b64url(crypto.getRandomValues(new Uint8Array(12))); lsSet(DEV_KEY, d); }
      return d;
    }
    function devName() {
      var ua = navigator.userAgent || '';
      if (/iPhone/.test(ua)) return 'iPhone';
      if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'iPad';
      if (/Android/.test(ua)) return 'Android';
      if (/Windows/.test(ua)) return 'Windows';
      if (/Macintosh/.test(ua)) return 'Mac';
      return 'その他';
    }

    function encodeCode(c) {
      var o = { u: c.u, k: c.k };
      if (c.e) o.e = c.e;
      return prefix + btoa(unescape(encodeURIComponent(JSON.stringify(o))));
    }
    function linkFor(c) { return location.origin + location.pathname + '#c=' + encodeURIComponent(encodeCode(c)); }

    // 貼り付けた文字列（招待コード・同期用リンク・コードそのもの）を読む
    // 前後の余計な文字・改行・全角コロン・二重貼り付け・小文字化があっても読めるように
    function decodeCode(s) {
      s = String(s || '');
      var h = /#c=([^#\s&]+)/.exec(s);
      if (h) { try { s = decodeURIComponent(h[1]); } catch (e) { s = h[1]; } }
      s = s.replace(/[\s​-‍⁠﻿]+/g, '').replace(/：/g, ':');
      var i = s.toUpperCase().indexOf(prefix);
      if (i < 0) {
        var inv = normInvite(s);
        return inv ? { u: url, k: inv } : null;
      }
      var body = s.slice(i + prefix.length);
      var next = body.toUpperCase().indexOf(prefix);
      if (next >= 0) body = body.slice(0, next);
      var m = /^[A-Za-z0-9+\/_-]+=*/.exec(body);
      if (!m) return null;
      body = m[0].replace(/-/g, '+').replace(/_/g, '/');
      while (body.length % 4) body += '=';
      try {
        var o = JSON.parse(decodeURIComponent(escape(atob(body))));
        if (!o || !okUrl(o.u) || typeof o.k !== 'string' || !o.k) return null;
        var c = { u: o.u, k: o.k };
        if (typeof o.e === 'string' && unb64(o.e).length === 32) c.e = o.e;
        return c;
      } catch (e) { return null; }
    }

    // 鍵から、暗号用（AES-GCM）と記録名用（HMAC）の2つを作る
    var keys = {};
    function keysFor(e) {
      if (!keys[e]) {
        var raw = unb64(e);
        keys[e] = Promise.all([
          crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']),
          crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']).then(function (base) {
            return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('record-name') },
              base, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
          })
        ]).then(function (k) { return { aes: k[0], mac: k[1] }; });
      }
      return keys[e];
    }
    // 記録名は鍵で作ったでたらめな文字列（h.〜）。本当の名前は暗号文の中に入れる
    function hid(k, id) {
      return crypto.subtle.sign('HMAC', k.mac, enc.encode(id)).then(function (s) { return 'h.' + b64url(s).slice(0, 22); });
    }
    // 記録名を追加認証データにして、別の記録と入れ替えられても気づけるようにする
    function seal(k, name, data) {
      var iv = crypto.getRandomValues(new Uint8Array(12));
      return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: enc.encode(name) }, k.aes, enc.encode(JSON.stringify(data)))
        .then(function (ct) { return { iv: b64(iv), ct: b64(ct) }; });
    }
    function open(k, name, r) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(r.iv), additionalData: enc.encode(name) }, k.aes, unb64(r.ct))
        .then(function (pt) { return JSON.parse(dec.decode(pt)); });
    }

    function post(conf, body) {
      body.token = conf.k;
      body.dev = devId();
      body.dn = devName();
      return fetch(conf.u, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify(body), redirect: 'follow' })
        .then(function (r) { return r.json().catch(function () { throw fail('server'); }); }, function () { throw fail('network'); })
        .then(function (j) { if (!j || !j.ok) throw fail((j && j.error) || 'server'); return j; });
    }

    // recs: [{id, u, data}] を暗号化して送り、サーバーで since より後に変わった記録を復号して返す
    // drop: 消してほしい記録名（以前の、名前がそのまま見える形式の記録）
    // 戻り値：{rev, recs: [{id, u, data}], legacy: [以前の形式の記録名]}
    function exchange(conf, since, recs, drop) {
      if (!conf || !conf.e) return Promise.reject(fail('no_key'));
      return keysFor(conf.e).then(function (k) {
        return Promise.all(recs.map(function (r) {
          return hid(k, r.id).then(function (name) {
            return seal(k, name, { i: r.id, d: r.data }).then(function (s) { return { id: name, u: r.u, iv: s.iv, ct: s.ct }; });
          });
        })).then(function (out) {
          return post(conf, { since: since || 0, recs: out, drop: drop || [] });
        }).then(function (j) {
          var list = j.recs || [], legacy = [];
          return Promise.all(list.map(function (r) {
            var isNew = r.id.indexOf('h.') === 0;
            if (!isNew) legacy.push(r.id);
            return open(k, r.id, r).then(function (d) {
              if (isNew) return d && typeof d.i === 'string' ? { id: d.i, u: +r.u || 0, data: d.d } : null;
              return { id: r.id, u: +r.u || 0, data: d };
            }, function () { return null; });
          })).then(function (got) {
            // 1件でも読めなければ鍵が違う。rev を進めずに止める
            if (got.some(function (x) { return !x; })) throw fail('bad_key');
            return { rev: +j.rev || 0, recs: got, legacy: legacy };
          });
        });
      });
    }

    // 接続：鍵入りの同期用リンクなら鍵が合うかを確かめる。鍵なしの招待コードは、空の保管場所に限り新しい鍵を作る
    function connect(s) {
      var c = decodeCode(s);
      if (!c) return Promise.reject(fail('bad_code'));
      if (c.e) return exchange(c, 0, []).then(function () { return c; });
      return post(c, { since: 0, recs: [] }).then(function (j) {
        if ((j.recs || []).length) throw fail('need_key');
        c.e = b64(crypto.getRandomValues(new Uint8Array(32)));
        return exchange(c, 0, [{ id: '_kc', u: Date.now(), data: { kc: 1 } }]).then(function () { return c; });
      });
    }

    return { encodeCode: encodeCode, linkFor: linkFor, decodeCode: decodeCode, exchange: exchange, connect: connect, message: message };
  }

  var MSG = {
    bad_code: '招待コードか同期用リンクを読み取れませんでした。招待コードは英数字8文字（XXXX-XXXX）です。リンクはすべて貼り付けてください。',
    bad_token: 'この招待コードは使えません。コードが違うか、許可が取り消された可能性があります。',
    need_key: 'この招待コードはすでにほかの端末で使われています。最初の端末で「同期用リンクをコピー」を押し、そのリンクを開くか貼ってください。',
    bad_key: '暗号の鍵が一致しません。最初の端末の「同期用リンク」を貼り直してください。',
    device_revoked: 'この端末は利用を取り消されています。管理者に確認してください。',
    device_limit: 'この招待コードで使える端末の数（上限）に達しています。管理者に、使っていない端末の取り消しか、上限を増やすよう頼んでください。',
    old_app: 'アプリが古い版です。いったん閉じて開き直してください。',
    network: '同期先につながりませんでした。インターネット接続を確認してください。',
    server: '同期サーバーが応答しませんでした。少し待ってから試してください。'
  };
  function message(code) { return MSG[code] || MSG.server; }

  g.E2ESync = { create: create, message: message };
})(window);
