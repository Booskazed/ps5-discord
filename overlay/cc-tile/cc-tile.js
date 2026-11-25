/*
 * cc-tile.js — Discord voice tile for the PS5 Control Center (NPXS40003).
 *
 * This script is evaluated INSIDE the Control Center's Hermes runtime, before
 * the app bundle runs, through a hook on
 *   ReactNative.JavaScriptCore.Executor.JSJavaScriptExecutor.RunScript(IJSBundle)
 * — the same door ZhiThemes uses to theme the Home (NPXS40002). The overlay
 * (overlay/src/core/worker.cpp, dedicated mode) installs that hook, and for the
 * bundle whose path contains "NPXS40003" it calls the private EvalScript(source,
 * url) with THIS file first, then lets the bundle run.
 *
 * It belongs to MY homebrew: it never touches the console's native Discord
 * (SceDiscordDaemon / Sce.Vsh.DiscordAccessor) and never touches PSN. The card
 * it will eventually show is fed only by my Discord port PPSA99073 (core at
 * 127.0.0.1). This file is pure display.
 *
 * Deploy (no rebuild needed once the hook ELF is installed): copy this file by
 * FTP to  /user/data/discord-overlay-poc/cc-tile.js  (ShellUI sees /user/data),
 * then reopen the Control Center.
 *
 * Logging: console.log lines prefixed "CCTILE" are captured by the overlay
 * (it hooks JSJavaScriptExecutor.ConsoleLog) and written to
 *   /user/data/discord-overlay-poc/worker.log
 *
 * ---------------------------------------------------------------------------
 * PHASE 1 (this file): prove our JS runs in the CC, steal Metro's `require`,
 * and find the module that exposes the ActionCardHost (strings confirmed in the
 * dumped bytecode: addActionCard / updateActionCard / removeActionCard, and the
 * host is an in-bundle service component app modules "connect to"). It does NOT
 * add a card yet: it discovers the host object and logs its method names so
 * phase 2 can connect() to it and addActionCard() correctly.
 */
(function () {
  'use strict';
  var TAG = 'CCTILE';
  function log(m) { try { console.log(TAG + ' ' + m); } catch (e) {} }

  if (globalThis.__ccTile) { log('already loaded in this context, skipping'); return; }
  var S = globalThis.__ccTile = { v: 1, mods: 0, host: null, hostId: null, found: [], mentions: [] };

  log('alive in Control Center  hermes=' + (typeof HermesInternal !== 'undefined') +
      '  console=' + (typeof console !== 'undefined') +
      '  setTimeout=' + (typeof setTimeout === 'function'));

  /* ---- reach Metro's require ------------------------------------------------
   * In these ShellUI bundles `require` is not global. Metro invokes each module
   * factory as  factory.call(module, module, exports, require)  — so module ===
   * thisArg, module.exports === exports, and require has .m (factories) and .c
   * (cache). We temporarily hook Function.prototype.call to catch the first such
   * call that carries a non-empty require, restore call, then wrap every factory
   * so we observe each module's exports as it is first required. (Same technique
   * as ZhiThemes' theme.js; kept minimal here.)
   */
  var callOriginal = Function.prototype.call;

  function factoryCount(req) {
    var n = 0;
    try { for (var k in req.m) { if (typeof req.m[k] === 'function') n++; } } catch (e) {}
    return n;
  }

  function fnKeys(o, max) {
    var out = [];
    try {
      var k = Object.keys(o);
      for (var i = 0; i < k.length && out.length < (max || 30); i++) {
        try { if (typeof o[k[i]] === 'function') out.push(k[i]); } catch (e) {}
      }
    } catch (e) {}
    return out;
  }

  function looksLikeHost(o) {
    if (!o || (typeof o !== 'object' && typeof o !== 'function')) return false;
    try { return (typeof o.addActionCard === 'function') || ('addActionCard' in o); }
    catch (e) { return false; }
  }

  /* Examine one module's exports for the ActionCardHost. */
  function inspect(exp, id) {
    if (!exp || (typeof exp !== 'object' && typeof exp !== 'function')) return;
    var keys;
    try { keys = Object.keys(exp); } catch (e) { return; }

    /* direct: the export itself carries the card API */
    if (looksLikeHost(exp)) {
      record(id, '', exp, keys);
      return;
    }
    /* nested one level: a default/host object on the exports */
    for (var i = 0; i < keys.length; i++) {
      var v;
      try { v = exp[keys[i]]; } catch (e) { continue; }
      if (looksLikeHost(v)) { record(id, '.' + keys[i], v, keys); return; }
    }
    /* otherwise, note modules that merely mention ActionCard (helps mapping) */
    for (var j = 0; j < keys.length; j++) {
      if (/ActionCard/.test(keys[j])) {
        if (S.mentions.length < 40) {
          S.mentions.push(id);
          log('mentions ActionCard: module ' + id + ' keys=[' +
              keys.filter(function (k) { return /ActionCard/.test(k); }).slice(0, 12).join(',') + ']');
        }
        return;
      }
    }
  }

  function record(id, where, host, keys) {
    var tag = id + where;
    if (S.found.indexOf(tag) >= 0) return;
    S.found.push(tag);
    if (!S.host) { S.host = host; S.hostId = tag; }
    log('HOST candidate: module ' + tag + '  export keys=[' + keys.slice(0, 18).join(',') + ']');
    log('  host methods: [' + fnKeys(host, 40).join(',') + ']');
    /* surface the connect / subscribe style methods specifically */
    var connectish = fnKeys(host, 60).filter(function (k) {
      return /connect|subscribe|client|host|session|open|register|init/i.test(k);
    });
    if (connectish.length) log('  connect-ish: [' + connectish.join(',') + ']');
  }

  function wrapRequire(require) {
    S.require = require;
    var m = require.m, n = 0;
    for (var id in m) {
      if (typeof m[id] === 'function') {
        (function (orig, mid) {
          m[mid] = function (module, exports, req) {
            var r = orig.call(this, module, exports, req);
            try { inspect(module && module.exports, mid); } catch (e) {}
            return r;
          };
        })(m[id], id);
        n++;
      }
    }
    S.mods = n;
    log('require caught, wrapped ' + n + ' module factories');
  }

  Function.prototype.call = function (thisArg, module, exports, require) {
    if (!S.hooked && arguments.length === 4 && typeof require === 'function' &&
        module && typeof module === 'object' && module.exports === exports &&
        exports === thisArg && require.m && require.c) {
      if (factoryCount(require) > 0) {
        S.hooked = true;
        Function.prototype.call = callOriginal;
        try { wrapRequire(require); } catch (e) { log('wrapRequire failed: ' + e); }
        var r = callOriginal.call(this, thisArg, module, exports, require);
        try { inspect(module.exports, module.i); } catch (e) {}
        return r;
      }
    }
    return callOriginal.apply(this, arguments);
  };

  /* Safety net: restore Function.prototype.call and print a summary even if the
     bundle never triggered the catch, so we are never left patched. */
  try {
    if (typeof setTimeout === 'function') {
      setTimeout(function () {
        if (Function.prototype.call !== callOriginal) Function.prototype.call = callOriginal;
        log('scan summary: modules=' + S.mods +
            '  hosts=[' + (S.found.join(' | ') || 'none') + ']' +
            '  mentions=' + S.mentions.length);
      }, 15000);
    }
  } catch (e) {}

  log('require-steal armed');
})();
