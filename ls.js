/*
 * iOS Frida `ls` 辅助脚本
 *
 * 在 Frida 里直接：
 *   ls()                       沙盒根目录
 *   ls("/var/...")             绝对路径
 *   ls("bundle")               主 bundle
 *   ls("docs/sub")             快捷方式 + 子路径
 *   ls("group:com.xxx.group")  App Group 容器
 *   ls.home() ls.bundle() ls.docs() ls.lib() ls.cache() ls.support() ls.tmp() ls.group(id)  链式快捷函数
 *   ls.paths()                 打印所有快捷方式对应的真实路径
 *   ls.help()                  用法说明
 *
 * 外部驱动（frida -q / Python / Node）可通过 rpc.exports.ls(path) 拿结构化结果。
 * 无权限或路径不存在时返回 { ok: false, error: "..." }，不抛异常。
 */

(function () {
  if (typeof ObjC === 'undefined' || !ObjC.available || !ObjC.classes.NSFileManager) {
    console.log('[ls] 需要已加载 Foundation 的 iOS 进程（ObjC 可用），脚本未加载');
    return;
  }

  // 按需修改：当只写 ls("group") 时使用的默认 App Group ID
  var DEFAULT_GROUP_ID = null;

  var NSDocumentDirectory = 9;
  var NSLibraryDirectory = 5;
  var NSCachesDirectory = 13;
  var NSApplicationSupportDirectory = 14;
  var NSUserDomainMask = 1;

  function errMsg(e) {
    return (e && (e.message || e.toString())) || '未知错误';
  }

  // NSError** 必须传可写的 NativePointer，传 JS null 会报 "expected a pointer"
  function errPtr() {
    try {
      return Memory.alloc(Process.pointerSize);
    } catch (e) {
      return ptr(0);
    }
  }

  function join(a, b) {
    if (!b) return a;
    return String(a).replace(/\/+$/, '') + '/' + String(b).replace(/^\/+/, '');
  }

  function padLeft(s, n) {
    s = String(s);
    while (s.length < n) s = ' ' + s;
    return s;
  }

  function padRight(s, n) {
    s = String(s);
    while (s.length < n) s += ' ';
    return s;
  }

  function str(obj) {
    if (obj === null || obj === undefined) return '';
    try {
      return ObjC.unwrap(obj).toString();
    } catch (e) {
      return obj.toString();
    }
  }

  // 兼容 NSArray 和已经被桥接成 JS 数组的情况
  function toNameArray(obj) {
    if (!obj) return null;
    try {
      if (typeof obj.count === 'function') {
        var n = obj.count();
        var out = [];
        for (var i = 0; i < n; i++) out.push(str(obj.objectAtIndex_(i)));
        return out;
      }
    } catch (e) {}
    if (typeof obj.length === 'number') {
      var arr = [];
      for (var j = 0; j < obj.length; j++) arr.push(str(obj[j]));
      return arr;
    }
    return null;
  }

  function findExport(name) {
    var addr = null;
    try { addr = Module.findExportByName(null, name); } catch (e) {}
    if (!addr || addr.isNull()) {
      try {
        if (typeof Module.findGlobalExportByName === 'function') {
          addr = Module.findGlobalExportByName(name);
        }
      } catch (e) {}
    }
    if (!addr || addr.isNull()) {
      try {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
          var m = modules[i];
          if (m.name === 'Foundation' || m.path.indexOf('/Foundation.framework/') !== -1) {
            addr = m.findExportByName(name);
            if (addr && !addr.isNull()) break;
          }
        }
      } catch (e) {}
    }
    return (addr && !addr.isNull()) ? addr : null;
  }

  function cString(fnName) {
    try {
      var addr = findExport(fnName);
      if (!addr) return null;
      var fn = new NativeFunction(addr, 'pointer', []);
      var ret = fn();
      if (ret.isNull()) return null;
      return ObjC.Object(ret).toString();
    } catch (e) {
      return null;
    }
  }

  function cSearchPath(directory) {
    try {
      var addr = findExport('NSSearchPathForDirectoriesInDomains');
      if (!addr) return null;
      var fn = new NativeFunction(addr, 'pointer', ['int', 'int', 'int']);
      var ret = fn(directory, NSUserDomainMask, 1);
      if (ret.isNull()) return null;
      return ObjC.Object(ret).objectAtIndex_(0).toString();
    } catch (e) {
      return null;
    }
  }

  function objcSearchPath(directory) {
    try {
      var urls = ObjC.classes.NSFileManager.defaultManager()
        .URLsForDirectory_inDomains_(directory, NSUserDomainMask);
      if (urls && typeof urls.count === 'function' && urls.count() > 0) {
        return urls.objectAtIndex_(0).path().toString();
      }
    } catch (e) {}
    return null;
  }

  function searchPath(directory) {
    return objcSearchPath(directory) || cSearchPath(directory);
  }

  function home() {
    var h = cString('NSHomeDirectory');
    if (h) return h;
    var d = searchPath(NSDocumentDirectory);
    if (d) {
      var base = d.replace(/\/Documents\/*$/, '');
      if (base && base !== d) return base;
    }
    return '/';
  }

  function bundle() {
    try {
      return ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
    } catch (e) {
      throw new Error('无法获取 bundle 路径：' + errMsg(e));
    }
  }

  function groupPath(gid) {
    var id = gid || DEFAULT_GROUP_ID;
    if (!id) {
      throw new Error('未指定 group identifier，用法：group("<id>") / ls.group("<id>") / ls("group:<id>")；也可设置 DEFAULT_GROUP_ID');
    }
    var url;
    try {
      url = ObjC.classes.NSFileManager.defaultManager()
        .containerURLForSecurityApplicationGroupIdentifier_(id);
    } catch (e) {
      throw new Error('无法获取 group 容器 ' + id + '：' + errMsg(e));
    }
    if (!url || (typeof url.isNil === 'function' && url.isNil())) {
      throw new Error('无法获取 group 容器 ' + id + '（identifier 不存在或无权限）');
    }
    return url.path().toString();
  }

  function documentsPath() { return searchPath(NSDocumentDirectory) || join(home(), 'Documents'); }
  function libraryPath() { return searchPath(NSLibraryDirectory) || join(home(), 'Library'); }
  function cachesPath() { return searchPath(NSCachesDirectory) || join(home(), 'Library/Caches'); }
  function supportPath() {
    return searchPath(NSApplicationSupportDirectory) || join(home(), 'Library/Application Support');
  }
  function tmpPath() { return cString('NSTemporaryDirectory') || join(home(), 'tmp'); }

  var shortcuts = {
    home: home,
    bundle: bundle,
    docs: documentsPath,
    lib: libraryPath,
    cache: cachesPath,
    support: supportPath,
    tmp: tmpPath,
    group: function () { return groupPath(DEFAULT_GROUP_ID); }
  };

  function resolvePath(input) {
    var raw = input === null || input === undefined ? '' : String(input).trim();
    if (raw === '' || raw === '.' || raw === '~') return home();
    if (raw.indexOf('group:') === 0) return groupPath(raw.slice(6));
    if (raw.charAt(0) === '/') return raw;
    if (raw.indexOf('~/') === 0) return join(home(), raw.slice(2));

    var slash = raw.indexOf('/');
    var head = (slash === -1 ? raw : raw.slice(0, slash)).toLowerCase();
    var rest = slash === -1 ? '' : raw.slice(slash + 1);
    if (shortcuts[head]) return join(shortcuts[head](), rest);
    return join(home(), raw);
  }

  function dateFormatter() {
    try {
      var f = ObjC.classes.NSDateFormatter.alloc().init();
      f.setDateFormat_('MM-dd HH:mm');
      return f;
    } catch (e) {
      return null;
    }
  }

  function typeChar(t) {
    if (t === 'NSFileTypeDirectory') return 'd';
    if (t === 'NSFileTypeSymbolicLink') return 'l';
    if (t === 'NSFileTypeRegular') return '-';
    if (t === 'NSFileTypeSocket') return 's';
    if (t === 'NSFileTypeCharacterSpecial') return 'c';
    if (t === 'NSFileTypeBlockSpecial') return 'b';
    if (t === 'NSFileTypeFIFO') return 'p';
    return '?';
  }

  function infoForPath(fm, full, name, attrs, fmt) {
    var type = '?';
    var size = '';
    var mtime = '';
    var link = '';

    try {
      type = typeChar(str(attrs.objectForKey_('NSFileType')));
    } catch (e) {}
    try {
      var s = attrs.objectForKey_('NSFileSize');
      if (s) size = str(s);
    } catch (e) {}
    try {
      var d = attrs.objectForKey_('NSFileModificationDate');
      if (d && fmt) mtime = str(fmt.stringFromDate_(d));
    } catch (e) {}
    if (type === 'l') {
      try {
        var dst = fm.destinationOfSymbolicLinkAtPath_error_(full, errPtr());
        if (dst) link = ' -> ' + str(dst);
      } catch (e) {}
    }

    return { name: name, type: type, size: size, mtime: mtime, link: link };
  }

  function lastComponent(p) {
    var parts = String(p).split('/').filter(function (x) { return x.length > 0; });
    return parts.length ? parts[parts.length - 1] : '/';
  }

  function list_dir(input) {
    var target;
    try {
      target = resolvePath(input);
    } catch (e) {
      return { ok: false, error: errMsg(e) };
    }

    var fm = ObjC.classes.NSFileManager.defaultManager();
    var fmt = dateFormatter();
    var rawNames = null;
    var listErr = null;

    try {
      rawNames = fm.contentsOfDirectoryAtPath_error_(target, errPtr());
    } catch (e) {
      listErr = e;
    }
    var names = toNameArray(rawNames);

    // 目录读不了时，尝试当作单个文件展示；仍然失败才报权限/不存在错误
    if (!names) {
      var attrs = null;
      try {
        attrs = fm.attributesOfItemAtPath_error_(target, errPtr());
      } catch (e) {}
      if (attrs) {
        var row = infoForPath(fm, target, lastComponent(target), attrs, fmt);
        return { ok: true, path: target, isFile: true, entries: [row] };
      }
      return {
        ok: false,
        path: target,
        error: '无法访问 ' + target + '：' + (listErr ? errMsg(listErr) : '路径不存在或没有权限')
      };
    }

    // 主 API 返回空时，用另一个 API 交叉验证，避免桥接差异导致漏列
    var source = 'contentsOfDirectoryAtPath';
    if (names.length === 0) {
      try {
        var subs = toNameArray(fm.subpathsOfDirectoryAtPath_error_(target, errPtr()));
        if (subs && subs.length > 0) {
          var top = [];
          subs.forEach(function (p) {
            var first = String(p).split('/')[0];
            if (first && top.indexOf(first) === -1) top.push(first);
          });
          if (top.length > 0) {
            names = top;
            source = 'subpathsOfDirectoryAtPath';
          }
        }
      } catch (e) {}
    }

    var entries = [];
    names.forEach(function (name) {
      var full = join(target, name);
      var itemAttrs = null;
      try {
        itemAttrs = fm.attributesOfItemAtPath_error_(full, errPtr());
      } catch (e) {}
      entries.push(infoForPath(fm, full, name, itemAttrs || {}, fmt));
    });
    entries.sort(function (a, b) {
      return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
    });

    return { ok: true, path: target, isFile: false, source: source, entries: entries };
  }

  function printResult(r) {
    if (!r.ok) {
      console.log('[ls] 错误: ' + r.error);
      return r;
    }
    console.log('[ls] ' + r.path + '  (' + r.entries.length + ' 项)');
    var width = 0;
    r.entries.forEach(function (e) { width = Math.max(width, e.name.length); });
    r.entries.forEach(function (e) {
      console.log('  ' + e.type + ' ' + padLeft(e.size, 10) + ' ' + padRight(e.mtime, 12) + ' ' + e.name + e.link);
    });
    return r;
  }

  function ls(input) {
    printResult(list_dir(input));
  }

  // 把快捷方式直接封装成函数：ls.bundle() / ls.document() / ls.group(id) ...
  function shortcutLs(key) {
    return function (subpath) {
      var base;
      try {
        base = shortcuts[key]();
      } catch (e) {
        return { ok: false, error: errMsg(e) };
      }
      printResult(list_dir(subpath ? join(base, subpath) : base));
    };
  }

  // 诊断：确认目录是否真的为空 / 哪种 API 能取到内容
  function debugPath(input) {
    var target;
    try {
      target = resolvePath(input);
    } catch (e) {
      return { error: errMsg(e) };
    }
    var fm = ObjC.classes.NSFileManager.defaultManager();
    var out = { path: target };
    try { out.exists = !!fm.fileExistsAtPath_(target); } catch (e) { out.exists = 'err: ' + errMsg(e); }
    try {
      var a = fm.attributesOfItemAtPath_error_(target, errPtr());
      out.type = a ? str(a.objectForKey_('NSFileType')) : null;
    } catch (e) { out.type = 'err: ' + errMsg(e); }
    try {
      var n = toNameArray(fm.contentsOfDirectoryAtPath_error_(target, errPtr()));
      out.contentsCount = n ? n.length : null;
      out.contentsSample = n ? n.slice(0, 8) : null;
    } catch (e) { out.contentsErr = errMsg(e); }
    try {
      var s = toNameArray(fm.subpathsOfDirectoryAtPath_error_(target, errPtr()));
      out.subpathsCount = s ? s.length : null;
      out.subpathsSample = s ? s.slice(0, 8) : null;
    } catch (e) { out.subpathsErr = errMsg(e); }
    console.log(JSON.stringify(out, null, 2));
    return out;
  }

  var CANONICAL = ['home', 'bundle', 'docs', 'lib', 'cache', 'support', 'tmp', 'group'];

  var SHORTCUT_DESC = {
    home: '沙盒根目录',
    bundle: 'App 主 bundle',
    docs: 'Documents 目录',
    lib: 'Library 目录',
    cache: 'Caches 缓存目录',
    support: 'Application Support 目录',
    tmp: '临时目录',
    group: 'App Group 共享容器'
  };

  function paths() {
    var out = {};
    Object.keys(shortcuts).forEach(function (k) {
      if (k === 'group' && !DEFAULT_GROUP_ID) {
        out[k] = '(未设置 DEFAULT_GROUP_ID，请用 group("<id>") / ls.group("<id>") / ls("group:<id>"))';
        return;
      }
      try {
        out[k] = shortcuts[k]();
      } catch (e) {
        out[k] = '错误: ' + errMsg(e);
      }
    });

    console.log('[ls] Usage: ls.<name>([subpath])');
    console.log('       ls.<name>("subpath")     list a subdirectory');
    console.log('       ls("<name>/subpath")     path form');
    console.log('       ls("/absolute/path")     absolute path');
    console.log('');
    console.log('[ls] Shortcuts:');
    CANONICAL.forEach(function (k) {
      console.log('  ' + padRight(k, 9) + padRight(SHORTCUT_DESC[k] || '', 30) + out[k]);
    });
    return out;
  }

  function help() {
    console.log([
      '[ls] 快捷函数（链式调用，可传子路径）：',
      '  ls.home()  ls.bundle()  ls.docs()  ls.lib()',
      '  ls.cache() ls.support() ls.tmp()   ls.group(id)',
      '[ls] 路径写法：',
      '  ls()                       沙盒根目录',
      '  ls("/absolute/path")       绝对路径',
      '  ls("bundle")               快捷方式名',
      '  ls("docs/sub")             快捷方式 + 子路径',
      '  ls("group:com.xxx.group")  App Group 容器',
      '  ls.paths()                 查看所有快捷方式对应路径',
      '  ls.debug("docs")           诊断目录是否真的为空',
      '  rpc.exports.ls(path)       外部驱动调用，返回 JSON',
      '  rpc.exports.bundle() 等    外部驱动调用快捷方式'
    ].join('\n'));
  }

  ls.paths = function () { paths(); };
  ls.help = help;
  ls.debug = function (input) { debugPath(input); };

  Object.keys(shortcuts).forEach(function (k) {
    if (k !== 'group') ls[k] = shortcutLs(k);
  });
  ls.group = function (id) {
    try {
      printResult(list_dir(groupPath(id)));
    } catch (e) {
      printResult({ ok: false, error: errMsg(e) });
    }
  };

  var g = null;
  if (typeof globalThis !== 'undefined') g = globalThis;
  else if (typeof global !== 'undefined') g = global;
  else if (typeof window !== 'undefined') g = window;
  else {
    try { g = Function('return this')(); } catch (e) { g = null; }
  }

  function cleanExported(fn) {
    var out = (...args) => fn(...args);
    try { delete out.length; } catch (e) {}
    try { delete out.name; } catch (e) {}
    try { Object.setPrototypeOf(out, null); } catch (e) {}
    Object.getOwnPropertyNames(fn).forEach(function (k) {
      if (k === 'length' || k === 'name' || k === 'prototype' || k === 'arguments' || k === 'caller') return;
      out[k] = fn[k];
    });
    return out;
  }
  if (g) {
    g.ls = cleanExported(ls);
  } else {
    console.log('[ls] 未找到全局对象，仅 rpc.exports 可用');
  }

  var rpcExports = { ls: list_dir, paths: paths };
  Object.keys(shortcuts).forEach(function (k) {
    if (k === 'group') return;
    rpcExports[k] = function (subpath) {
      try {
        var base = shortcuts[k]();
        return list_dir(subpath ? join(base, subpath) : base);
      } catch (e) {
        return { ok: false, error: errMsg(e) };
      }
    };
  });
  rpcExports.group = function (id) {
    try {
      return list_dir(groupPath(id));
    } catch (e) {
      return { ok: false, error: errMsg(e) };
    }
  };
  rpcExports.debug = debugPath;
  rpc.exports = rpcExports;

  if (g) {
    var reg = g.__fridaApi || (g.__fridaApi = { scripts: {} });
    reg.scripts.ls = ['ls()', 'ls.help()', 'ls.paths()', 'ls.debug()',
                      'ls.home()', 'ls.bundle()', 'ls.docs()', 'ls.lib()', 'ls.cache()',
                      'ls.support()', 'ls.tmp()', 'ls.group(id)'];
    if (!g.api) {
      g.api = function () {
        var r = g.__fridaApi || { scripts: {} };
        console.log('[api] 已加载脚本的公开函数：');
        Object.keys(r.scripts).sort().forEach(function (name) {
          console.log('  ' + name + ': ' + r.scripts[name].join(', '));
        });
      };
    }
  }
})();
