(function () {
  'use strict';

  var SALT = 'dongspoon2|v1';
  var ITER = 150000;
  var ALPHA = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  var SEX = { M: '남성', F: '여성' };
  var SELECT_URL = 'https://ambiguous-scilla-52c.notion.site/dongspoon2';
  var INFO = [
    '1차 매칭 대상은 기본적으로 정량화할 수 있는 조건 (나이, 키, 학교, 지역 등)을 기준으로 “본인 조건에 부합하는 이성의 조건에 부합하는 본인”, 즉 교집합에 속하는 사람들입니다. 한정된 참여자들 내에서 매칭이 이루어지다보니 조건 교집합에 부합하는 이성의 수가 부족한 경우가 있습니다. 모든 참가자분들께 최소 수의 이성 프로필 제공 보장을 위하여 양쪽의 조건 교집합 수가 적은 경우 자동으로 키/나이 등을 조금씩 +-조절하면서 조합을 생성하도록 자동화하였습니다. 결과적으로 제공받은 이성 프로필 중 본인이 입력했던 정량 조건에 완전히 포함되지 않는 경우가 있을 수 있습니다.',
    '이성 프로필은 이름/연락처를 제외하고 넘버링 되어 공유되며, 한 페이지에 포함된 정보들이 한 사람의 프로필입니다. 프로필을 확인 후 최대 3명에게 데이트 신청을 할 수 있으며, 본인이 먼저 신청하지 않더라도 상대방이 데이트 신청을 한다면 만나보고 싶은 분을 최대 M명 선택할 수 있습니다.',
    '이성 프로필 선택은 위 링크 소개팅 안내 페이지의 [이성 선택] 탭의 양식을 작성하시면 되며, 내일 밤인 "10/4(일) 자정까지" 입력을 마쳐주셔야 합니다.'
  ];
  var app = document.getElementById('app');
  var te = new TextEncoder();
  var td = new TextDecoder();
  var S = { data: null, items: [], byId: {}, packs: {}, seen: {}, listY: 0, pushed: false, wm: '' };

  if ('scrollRestoration' in history) history.scrollRestoration = 'manual';

  /* ---------- small helpers ---------- */
  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        var v = attrs[k];
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : v);
      }
    }
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  function add(el, c) {
    if (c == null || c === false) return;
    if (Array.isArray(c)) { for (var i = 0; i < c.length; i++) add(el, c[i]); return; }
    el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  function mount() {
    app.textContent = '';
    for (var i = 0; i < arguments.length; i++) add(app, arguments[i]);
  }
  function getItem(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function setItem(k, v) { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { /* storage blocked */ } }
  function normCode(s) {
    return String(s || '').toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1').replace(/[^0-9A-Z]/g, '');
  }
  function validCode(s) {
    if (s.length !== 16) return false;
    for (var i = 0; i < s.length; i++) if (ALPHA.indexOf(s.charAt(i)) < 0) return false;
    return true;
  }
  function hex(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16);
    return s;
  }
  function unb64(s) {
    var bin = atob(s), u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function hashCode() {
    var raw = location.hash.replace(/^#/, '');
    if (!raw) {
      var m = location.search.match(/[?&]k=([^&#]+)/);
      if (m) raw = m[1];
    }
    try { raw = decodeURIComponent(raw); } catch (e) { /* keep raw */ }
    return normCode(raw);
  }
  function label(x) { return SEX[x.s] + ' ' + x.n + '번'; }

  /* ---------- crypto ---------- */
  async function derive(code) {
    var base = await crypto.subtle.importKey('raw', te.encode(code), 'PBKDF2', false, ['deriveBits']);
    var bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: te.encode(SALT), iterations: ITER, hash: 'SHA-256' }, base, 384));
    var key = await crypto.subtle.importKey('raw', bits.slice(0, 32), { name: 'AES-GCM' }, false, ['decrypt']);
    return { key: key, id: hex(bits.slice(32, 48)) };
  }
  async function decrypt(key, buf) {
    var u = new Uint8Array(buf);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12)));
  }
  async function getBin(url, fresh) {
    var r = await fetch(url, fresh ? { cache: 'no-cache' } : {});
    if (r.status === 404) { var e = new Error('notfound'); e.notfound = true; throw e; }
    if (!r.ok) throw new Error('http ' + r.status);
    return r.arrayBuffer();
  }
  function getPack(x) {
    if (S.packs[x.id]) return S.packs[x.id];
    var p = (async function () {
      var key = await crypto.subtle.importKey('raw', unb64(x.k), { name: 'AES-GCM' }, false, ['decrypt']);
      var plain = await decrypt(key, await getBin('d/p/' + x.p + '.bin', false));
      if (td.decode(plain.subarray(0, 4)) !== 'DSP1') throw new Error('bad pack');
      var hl = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(4);
      var head = JSON.parse(td.decode(plain.subarray(8, 8 + hl)));
      var base = 8 + hl;
      return head.ph.map(function (q) {
        var blob = new Blob([plain.subarray(base + q.o, base + q.o + q.l)], { type: 'image/jpeg' });
        return { url: URL.createObjectURL(blob), w: q.w, h: q.h };
      });
    })();
    S.packs[x.id] = p;
    p.catch(function () { delete S.packs[x.id]; });
    return p;
  }
  function prefetch(x) {
    if (!x || S.packs[x.id]) return;
    setTimeout(function () { getPack(x).catch(function () {}); }, 700);
  }

  /* ---------- boot ---------- */
  async function boot() {
    if (!window.crypto || !crypto.subtle || !window.fetch || !window.TextDecoder) {
      return gate('이 브라우저에서는 열 수 없어요. 최신 버전의 크롬이나 사파리로 열어 주세요.');
    }
    var fromHash = hashCode();
    var code = fromHash || normCode(getItem('ds2:code'));
    if (!code) return gate();
    if (!validCode(code)) return gate('링크 주소가 올바르지 않아요. 받으신 링크를 다시 눌러 주세요.');
    loading('프로필을 여는 중…');
    try {
      var d = await derive(code);
      var plain = await decrypt(d.key, await getBin('d/v/' + d.id + '.bin', true));
      start(code, JSON.parse(td.decode(plain)));
    } catch (e) {
      if (e && (e.notfound || e.name === 'OperationError')) {
        if (!fromHash) setItem('ds2:code', null);
        return gate('이 링크로는 프로필을 찾을 수 없어요. 받으신 링크를 다시 확인해 주세요.');
      }
      errorView('불러오지 못했어요. 인터넷 연결을 확인한 뒤 다시 시도해 주세요.');
    }
  }

  function start(code, data) {
    setItem('ds2:code', code);
    S.data = data;
    S.meLabel = label(data.me);
    S.meName = String(data.me.name || '').trim();
    S.items = data.items.slice().sort(function (a, b) { return a.n - b.n; });
    S.byId = {};
    S.items.forEach(function (x, i) { x.i = i; S.byId[x.id] = x; });
    S.seenKey = 'ds2:seen:' + data.me.s + data.me.n;
    S.seen = {};
    try { JSON.parse(getItem(S.seenKey) || '[]').forEach(function (id) { S.seen[id] = 1; }); } catch (e) { /* ignore */ }
    S.wm = S.meLabel + ' 열람용';
    route();
  }

  function route() {
    var st = history.state;
    if (st && st.p && S.byId[st.p]) showProfile(S.byId[st.p]);
    else showList();
  }

  /* ---------- views ---------- */
  function logo(cls) {
    return h('img', { class: cls || 'logo', src: 'img/logo.png', alt: '동스푼', width: '134', height: '132' });
  }
  function topbar(title) {
    if (!title) {
      return h('header', { class: 'masthead' }, logo(), h('span', { class: 'season', text: 'Season 2' }));
    }
    return h('header', { class: 'top' },
      h('button', { class: 'back', type: 'button', onclick: backToList, 'aria-label': '목록으로' }, '‹ 목록'),
      h('div', { class: 'title', text: title }));
  }

  function notice(short) {
    return h('section', { class: 'notice' },
      h('h2', { text: '꼭 지켜 주세요' }),
      h('ul', null,
        h('li', { text: '이 링크는 받으신 분 전용이에요. 다른 사람에게 보내지 말아 주세요.' }),
        h('li', { text: '프로필과 사진의 캡처·저장·공유는 금지돼요. 사진에는 열람자 표시가 들어가 있어요.' }),
        short ? null : h('li', { text: '궁금한 점은 동스푼 운영진에게 카카오톡으로 문의해 주세요.' })));
  }

  function info() {
    return h('section', { class: 'notice info' },
      h('h2', { text: '매칭 안내' }),
      h('ul', null, INFO.map(function (t) { return h('li', { text: t }); })));
  }

  // Korean copula after a number read aloud: 1 일·3 삼·6 육·7 칠·8 팔·0 영 → 이에요, 2 이·4 사·5 오·9 구 → 예요
  function copula(n) {
    return '2459'.indexOf(String(n).slice(-1)) >= 0 ? '예요' : '이에요';
  }

  function showList() {
    document.title = '동스푼2';
    var tiles = S.items.map(function (x) {
      var seen = !!S.seen[x.id];
      return h('button', {
        class: 'tile' + (seen ? ' seen' : ''), type: 'button',
        'aria-label': label(x) + ' 프로필 보기' + (seen ? ' (확인함)' : ''),
        onclick: function () { openProfile(x); }
      },
        h('span', { class: 'sx', text: SEX[x.s] }),
        h('span', { class: 'nm', text: x.n + '번' }),
        seen ? h('span', { class: 'chk', 'aria-hidden': 'true', text: '확인' }) : null);
    });
    mount(
      topbar(),
      h('main', { class: 'wrap' },
        h('section', { class: 'hello' },
          h('img', { class: 'plate', src: 'img/plate.png', alt: '', 'aria-hidden': 'true', width: '106', height: '106' }),
          h('p', { class: 'who', text: S.meLabel + (S.meName ? ' ' + S.meName : '') + '님,' }),
          h('h1', { text: '1차 매칭된 분은 ' + S.items.length + '명이에요' }),
          S.data.m ? h('p', { class: 'mval' },
            (S.meName || S.meLabel) + '님의 M값은 ', h('b', { text: '“' + S.data.m + '”' }), copula(S.data.m)) : null,
          h('p', { class: 'sub', text: '번호를 누르면 프로필과 사진을 볼 수 있어요.' })),
        h('div', { class: 'grid' }, tiles),
        h('a', { class: 'cta', href: SELECT_URL, target: '_blank', rel: 'noopener noreferrer' }, '2차 매칭 이성 선택하러 가기'),
        h('p', { class: 'cta-note', text: '10/4(일) 자정까지 입력해 주세요' }),
        notice(false),
        info(),
        h('div', { class: 'foot' }, logo('foot-logo'))));
    window.scrollTo(0, S.listY || 0);
  }

  function row(f) {
    var v = String(f[1] || '').trim();
    return h('div', { class: 'row' }, h('dt', { text: f[0] }), h('dd', { class: v ? null : 'empty', text: v || '-' }));
  }

  function showProfile(x) {
    markSeen(x.id);
    var name = label(x);
    document.title = name + ' · 동스푼2';
    var fields = x.f.filter(function (f) { return f[0] !== '추천사'; });
    var rec = x.f.filter(function (f) { return f[0] === '추천사'; })[0];
    var photos = h('div', { class: 'photos' });
    var figs = (x.d || []).map(function (wh) {
      var fig = h('figure', { class: 'ph' }, h('div', { class: 'ld' }, h('div', { class: 'spinner', 'aria-hidden': 'true' })));
      fig.style.aspectRatio = wh[0] + ' / ' + wh[1];
      photos.appendChild(fig);
      return fig;
    });
    var prev = S.items[x.i - 1], next = S.items[x.i + 1];
    mount(
      topbar(name),
      h('main', { class: 'wrap profile' },
        h('h1', { class: 'pname', text: name }),
        h('section', { class: 'card' }, h('dl', { class: 'fields' }, fields.map(row))),
        rec ? h('section', { class: 'card rec' }, h('dl', { class: 'fields' }, row(rec))) : null,
        h('h2', { class: 'sec-title' }, '사진', h('span', { text: figs.length + '장' })),
        photos,
        h('nav', { class: 'pager', 'aria-label': '다른 프로필' },
          h('button', { type: 'button', disabled: !prev, onclick: function () { if (prev) switchProfile(prev); } },
            prev ? '‹ ' + label(prev) : '‹ 이전'),
          h('button', { type: 'button', class: 'mid', onclick: backToList }, '목록'),
          h('button', { type: 'button', disabled: !next, onclick: function () { if (next) switchProfile(next); } },
            next ? label(next) + ' ›' : '다음 ›')),
        notice(true)));
    window.scrollTo(0, 0);
    loadPhotos(x, figs);
  }

  async function loadPhotos(x, figs) {
    try {
      var list = await getPack(x);
      if (!figs.length || !figs[0].isConnected) return;
      list.forEach(function (u, i) {
        var fig = figs[i];
        if (!fig) return;
        var img = h('img', { alt: label(x) + ' 사진 ' + (i + 1), width: u.w, height: u.h, draggable: 'false', decoding: 'async' });
        img.onload = function () { img.classList.add('on'); fig.classList.add('done'); };
        img.src = u.url;
        fig.insertBefore(img, fig.firstChild);
        fig.appendChild(h('div', { class: 'shield', 'aria-hidden': 'true' }));
        fig.appendChild(h('div', { class: 'wm', 'aria-hidden': 'true', text: S.wm }));
      });
      prefetch(S.items[x.i + 1]);
    } catch (e) {
      figs.forEach(function (fig) {
        if (!fig.isConnected) return;
        fig.classList.add('done');
        fig.appendChild(h('div', { class: 'fail' }, '사진을 불러오지 못했어요',
          h('button', { class: 'btn ghost', type: 'button', onclick: function () { showProfile(x); } }, '다시 시도')));
      });
    }
  }

  function openProfile(x) {
    S.listY = window.scrollY || window.pageYOffset || 0;
    history.pushState({ p: x.id }, '', location.href);
    S.pushed = true;
    showProfile(x);
  }
  function switchProfile(x) {
    history.replaceState({ p: x.id }, '', location.href);
    showProfile(x);
  }
  function backToList() {
    if (S.pushed && history.state && history.state.p) { history.back(); return; }
    history.replaceState(null, '', location.href);
    showList();
  }
  function markSeen(id) {
    if (S.seen[id]) return;
    S.seen[id] = 1;
    setItem(S.seenKey, JSON.stringify(Object.keys(S.seen)));
  }

  function loading(msg) {
    mount(h('div', { class: 'center' }, h('div', { class: 'spinner', 'aria-hidden': 'true' }), h('p', { class: 'muted', text: msg })));
  }
  function errorView(msg) {
    mount(h('div', { class: 'center' }, h('p', { text: msg }), h('button', { class: 'btn', type: 'button', onclick: boot }, '다시 시도')));
  }
  function gate(err) {
    var input = h('input', {
      type: 'text', autocomplete: 'off', autocapitalize: 'characters', autocorrect: 'off', spellcheck: 'false',
      maxlength: '24', placeholder: '코드 16자리', 'aria-label': '개인 코드 16자리'
    });
    mount(h('main', { class: 'gate' },
      logo(),
      h('h1', { text: '개인 링크로 들어와 주세요' }),
      h('p', { text: '카카오톡으로 받은 링크를 누르면 바로 열려요. 링크가 열리지 않으면 링크 맨 끝(# 뒤)의 코드 16자리를 입력해 주세요.' }),
      err ? h('p', { class: 'err', role: 'alert', text: err }) : null,
      h('form', {
        onsubmit: function (ev) {
          ev.preventDefault();
          var c = normCode(input.value);
          if (!validCode(c)) { gate('코드 16자리를 다시 확인해 주세요.'); return; }
          if (hashCode() === c) location.reload(); else location.hash = c;
        }
      }, input, h('button', { class: 'btn', type: 'submit' }, '열기'))));
  }

  window.addEventListener('popstate', function () { if (S.data) route(); });
  window.addEventListener('hashchange', function () { location.reload(); });
  document.addEventListener('contextmenu', function (e) {
    if (e.target && e.target.closest && e.target.closest('.ph')) e.preventDefault();
  });

  boot();
})();
