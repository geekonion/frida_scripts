/*
 * iOS Frida：直接从二进制的代码签名里读取 entitlements
 *
 * 路径：Mach-O -> LC_CODE_SIGNATURE -> CSMAGIC_EMBEDDED_SIGNATURE
 *       -> CSSLOT_ENTITLEMENTS (7) -> CSMAGIC_ENTITLEMENTS -> plist 字节
 *
 * 用法：
 *   ent()                       当前 App
 *   ent("/path/to/App.app")     指定 bundle / 可执行文件
 *   rpc.exports.entitlements()  返回 JSON
 */

(function () {
  if (typeof ObjC === 'undefined' || !ObjC.available) {
    console.log('[ent] 需要 ObjC 环境，脚本未加载');
    return;
  }

  function errMsg(e) {
    return (e && (e.message || e.toString())) || '未知错误';
  }

  function findExport(name) {
    var addr = null;
    try { addr = Module.findExportByName(null, name); } catch (e) {}
    if (addr && !addr.isNull()) return addr;
    try {
      if (typeof Module.findGlobalExportByName === 'function') {
        addr = Module.findGlobalExportByName(name);
        if (addr && !addr.isNull()) return addr;
      }
    } catch (e) {}
    try {
      var modules = Process.enumerateModules();
      for (var i = 0; i < modules.length; i++) {
        var m = modules[i];
        if (m.name.indexOf('Security') !== -1 || m.name.indexOf('CoreFoundation') !== -1 ||
            m.path.indexOf('Security.framework') !== -1 ||
            m.path.indexOf('CoreFoundation.framework') !== -1) {
          addr = m.findExportByName(name);
          if (addr && !addr.isNull()) return addr;
        }
      }
    } catch (e) {}
    return null;
  }

  // 只用来取 identifier；entitlements 完全来自下面的二进制解析
  var aCreate = findExport('SecStaticCodeCreateWithPath');
  var aCopy = findExport('SecCodeCopySigningInformation');
  var aStr = findExport('CFStringCreateWithCString');
  var aGet = findExport('CFDictionaryGetValue');
  var aRelease = findExport('CFRelease');
  var aPlistData = findExport('CFPropertyListCreateData');

  var secCreate = aCreate ? new NativeFunction(aCreate, 'int', ['pointer', 'uint', 'pointer']) : null;
  var secCopy = aCopy ? new NativeFunction(aCopy, 'int', ['pointer', 'uint', 'pointer']) : null;
  var cfStrCreate = aStr ? new NativeFunction(aStr, 'pointer', ['pointer', 'pointer', 'uint']) : null;
  var cfDictGet = aGet ? new NativeFunction(aGet, 'pointer', ['pointer', 'pointer']) : null;
  var cfRelease = aRelease ? new NativeFunction(aRelease, 'void', ['pointer']) : null;
  var cfPlistToData = aPlistData
    ? new NativeFunction(aPlistData, 'pointer', ['pointer', 'pointer', 'uint', 'int', 'pointer'])
    : null;

  var kCFStringEncodingUTF8 = 0x08000100;

  function cfKey(s) {
    return cfStrCreate(ptr(0), Memory.allocUtf8String(s), kCFStringEncodingUTF8);
  }

  function dictValue(dict, key) {
    if (!dict || dict.isNull() || !cfDictGet) return null;
    var k = cfKey(key);
    var v = cfDictGet(dict, k);
    if (!k.isNull() && cfRelease) cfRelease(k);
    return v;
  }

  function cfString(ref) {
    if (!ref || ref.isNull()) return null;
    try { return new ObjC.Object(ref).toString(); } catch (e) { return null; }
  }

  function le32(b, o) {
    return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  }

  function be32(b, o) {
    return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  }

  function findPatternU8(b, pat) {
    for (var i = 0; i <= b.length - pat.length; i++) {
      var ok = true;
      for (var j = 0; j < pat.length; j++) {
        if (b[i + j] !== pat[j]) { ok = false; break; }
      }
      if (ok) return i;
    }
    return -1;
  }

  function readFile(path) {
    try {
      var data = ObjC.classes.NSData.dataWithContentsOfFile_(path);
      if (!data) return null;
      var len = data.length();
      if (len < 32) return null;
      var base = data.bytes();
      return { base: base, len: len, u8: new Uint8Array(base.readByteArray(len)) };
    } catch (e) {
      return null;
    }
  }

  // 从 Mach-O 里定位 entitlements plist 的字节区间
  function plistRangeFromBinary(path) {
    var f = readFile(path);
    if (!f) {
      console.log('[ent] 读取二进制失败: ' + path);
      return null;
    }
    var u8 = f.u8;
    var sliceOff = 0;
    var sliceLen = f.len;
    var magicBe = be32(u8, 0);
    var magic = le32(u8, 0);

    // FAT / 通用二进制：选 arm64 slice
    if (magicBe === 0xcafebabe || magicBe === 0xbebafeca) {
      var nfat = be32(u8, 4);
      var found = false;
      for (var a = 0; a < nfat; a++) {
        var ao = 8 + a * 20;
        if (ao + 20 > f.len) break;
        if (be32(u8, ao) === 0x0100000c) {
          sliceOff = be32(u8, ao + 8);
          sliceLen = be32(u8, ao + 12);
          found = true;
          break;
        }
      }
      if (!found) {
        console.log('[ent] FAT 二进制里没有 arm64 slice');
        return null;
      }
      magic = le32(u8, sliceOff);
    }

    if (magic !== 0xfeedfacf && magic !== 0xfeedface) {
      console.log('[ent] magic 不是 Mach-O: le=' + magic.toString(16) + ' be=' + magicBe.toString(16));
      return null;
    }
    var headerSize = (magic === 0xfeedfacf) ? 32 : 28;
    var ncmds = le32(u8, sliceOff + 16);

    var p = sliceOff + headerSize;
    var codeOff = -1;
    var codeSize = 0;
    for (var i = 0; i < ncmds && p + 8 <= sliceOff + sliceLen; i++) {
      var cmd = le32(u8, p);
      var cmdsize = le32(u8, p + 4);
      if (cmdsize < 8) break;
      if (cmd === 0x1d) {
        codeOff = sliceOff + le32(u8, p + 8);
        codeSize = le32(u8, p + 12);
        break;
      }
      p += cmdsize;
    }
    if (codeOff < 0) {
      console.log('[ent] 没有 LC_CODE_SIGNATURE');
      return null;
    }
    if (codeOff + codeSize > f.len) {
      console.log('[ent] 签名区越界 off=' + codeOff + ' size=' + codeSize + ' len=' + f.len);
      return null;
    }

    var cs = u8.subarray(codeOff, codeOff + codeSize);
    var csMagic = be32(cs, 0);
    if (cs.length < 12 || csMagic !== 0xfade0cc0) return null;

    var count = be32(cs, 8);

    for (var k = 0; k < count; k++) {
      var ki = 12 + k * 8;
      if (ki + 8 > cs.length) break;
      if (be32(cs, ki) !== 7) continue;
      var off = be32(cs, ki + 4);
      if (off + 8 > cs.length) return null;
      var entMagic = be32(cs, off);
      if (entMagic !== 0xfade7171 && entMagic !== 0xfade7172) {
        console.log('[ent] entitlements blob magic=' + entMagic.toString(16));
        return null;
      }
      var blobLen = be32(cs, off + 4);
      var payloadLen = Math.min(blobLen - 8, cs.length - off - 8);
      if (payloadLen <= 0) return null;

      var payload = u8.subarray(codeOff + off + 8, codeOff + off + 8 + payloadLen);
      var inner = findPatternU8(payload, [0x3c, 0x3f, 0x78, 0x6d, 0x6c]);  // <?xml
      if (inner < 0) inner = findPatternU8(payload, [0x62, 0x70, 0x6c, 0x69, 0x73, 0x74]); // bplist
      if (inner > 0) {
        payloadLen -= inner;
      } else if (inner < 0) {
        inner = 0;
      }
      return { ptr: f.base.add(codeOff + off + 8 + inner), len: payloadLen };
    }
    console.log('[ent] 签名 blob 中没有 type=7');
    return null;
  }

  function xmlToObject(xml) {
    var out = {};
    var m;
    var re = /<key>([^<]*)<\/key>\s*(<string>[^<]*<\/string>|<true\s*\/>|<false\s*\/>|<integer>[^<]*<\/integer>)/g;
    while ((m = re.exec(xml)) !== null) {
      var key = m[1];
      var v = m[2];
      if (v.indexOf('<string>') === 0) out[key] = v.slice(8, -9);
      else if (v.indexOf('<true') === 0) out[key] = true;
      else if (v.indexOf('<false') === 0) out[key] = false;
      else out[key] = Number(v.replace(/<[^>]+>/g, ''));
    }
    var arrRe = /<key>([^<]*)<\/key>\s*<array>([\s\S]*?)<\/array>/g;
    while ((m = arrRe.exec(xml)) !== null) {
      var items = [];
      var sr = /<string>([^<]*)<\/string>/g;
      var sm;
      while ((sm = sr.exec(m[2])) !== null) items.push(sm[1]);
      out[m[1]] = items;
    }
    return out;
  }

  function derTLV(u8, p) {
    if (p + 2 > u8.length) return null;
    var tag = u8[p];
    var len = u8[p + 1];
    var hs = 2;
    if (len & 0x80) {
      var n = len & 0x7f;
      if (!n || p + 2 + n > u8.length) return null;
      len = 0;
      for (var i = 0; i < n; i++) len = (len << 8) | u8[p + 2 + i];
      hs = 2 + n;
    }
    return { tag: tag, len: len, start: p + hs, end: p + hs + len, next: p + hs + len };
  }

  function derString(u8, t) {
    var s = '';
    for (var i = t.start; i < t.end; i++) s += String.fromCharCode(u8[i]);
    return s;
  }

  // DER 形式的 entitlements：SEQUENCE { UTF8String key, value }
  function parseDerEntitlements(u8) {
    var out = {};
    for (var p = 0; p + 2 <= u8.length; p++) {
      if (u8[p] !== 0x30) continue;
      var t = derTLV(u8, p);
      if (!t || t.end > u8.length || t.len < 4) continue;
      var k = derTLV(u8, t.start);
      if (!k || k.tag !== 0x0c || k.end > t.end) continue;
      var v = derTLV(u8, k.next);
      if (!v || v.end > t.end) continue;
      var key = derString(u8, k);
      var val;
      if (v.tag === 0x0c) {
        val = derString(u8, v);
      } else if (v.tag === 0x01) {
        val = v.len > 0 && u8[v.start] !== 0;
      } else if (v.tag === 0x30) {
        val = [];
        var q = v.start;
        while (q < v.end) {
          var it = derTLV(u8, q);
          if (!it || it.end > v.end) break;
          if (it.tag === 0x0c) val.push(derString(u8, it));
          q = it.next;
        }
      } else {
        continue;
      }
      out[key] = val;
      p = t.next - 1;
    }
    return Object.keys(out).length ? out : null;
  }

  function decodePlistBytes(range) {
    try {
      var der = parseDerEntitlements(new Uint8Array(range.ptr.readByteArray(range.len)));
      if (der) return der;
    } catch (e) {}

    try {
      var ns = ObjC.classes.NSString.alloc()
        .initWithBytes_length_encoding_(range.ptr, range.len, 4);
      if (ns) {
        var xml = ns.toString();
        if (xml.indexOf('<plist') >= 0) {
          var out = xmlToObject(xml);
          if (Object.keys(out).length) return out;
        }
      }
    } catch (e) {}

    // 二进制 plist：转成 XML 后再走同一套解析
    if (cfPlistToData && cfRelease) {
      try {
        var data = ObjC.classes.NSData.dataWithBytes_length_(range.ptr, range.len);
        var fmtSlot = Memory.alloc(Process.pointerSize);
        var errSlot = Memory.alloc(Process.pointerSize);
        var plist = ObjC.classes.NSPropertyListSerialization
          .propertyListFromData_mutabilityOption_format_errorDescription_(data, 0, fmtSlot, errSlot);
        if (plist) {
          var xdataRef = cfPlistToData(ptr(0), plist.handle, 100, 0, errSlot);
          if (!xdataRef.isNull()) {
            var xns = ObjC.classes.NSString.alloc().initWithData_encoding_(
              new ObjC.Object(xdataRef), 4);
            cfRelease(xdataRef);
            if (xns) {
              var xout = xmlToObject(xns.toString());
              if (Object.keys(xout).length) return xout;
            }
          }
        }
      } catch (e) {}
    }
    return null;
  }

  function identifierFromSigning(path) {
    if (!secCreate || !secCopy || !cfRelease) return null;
    try {
      var url = ObjC.classes.NSURL.fileURLWithPath_(path);
      var slot = Memory.alloc(Process.pointerSize);
      if (secCreate(url.handle, 0, slot) !== 0) return null;
      var code = slot.readPointer();
      var islot = Memory.alloc(Process.pointerSize);
      if (secCopy(code, 0, islot) !== 0) { cfRelease(code); return null; }
      var info = islot.readPointer();
      var id = cfString(dictValue(info, 'identifier'));
      cfRelease(info);
      cfRelease(code);
      return id;
    } catch (e) {
      return null;
    }
  }

  function getInfo(input) {
    var bundlePath = input || ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
    var exePath = bundlePath;
    try {
      var b = ObjC.classes.NSBundle.bundleWithPath_(bundlePath);
      if (b) exePath = b.executablePath().toString();
    } catch (e) {}

    var range = plistRangeFromBinary(exePath);
    var entitlements = range ? decodePlistBytes(range) : null;

    var out = {
      path: exePath,
      identifier: identifierFromSigning(exePath) ||
                  ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey_('CFBundleIdentifier').toString(),
      entitlements: entitlements
    };

    if (entitlements) {
      out.teamId = entitlements['com.apple.developer.team-identifier'] || null;
      if (!out.teamId && typeof entitlements['application-identifier'] === 'string') {
        var aid = entitlements['application-identifier'];
        var dot = aid.indexOf('.');
        if (dot > 0) out.teamId = aid.slice(0, dot);
      }
    } else {
      out.teamId = null;
      if (!range) console.log('[ent] 未在二进制中找到 LC_CODE_SIGNATURE / entitlements blob');
    }
    return out;
  }

  function printInfo(info) {
    console.log('[ent] ' + info.path);
    console.log('  identifier: ' + (info.identifier || '-'));
    console.log('  teamid:     ' + (info.teamId || '-'));
    console.log('  entitlements:');
    var e = (info.entitlements && typeof info.entitlements === 'object') ? info.entitlements : {};
    var keys = Object.keys(e).sort();
    if (!keys.length) console.log('    (无)');
    else keys.forEach(function (k) { console.log('    ' + k + ' = ' + JSON.stringify(e[k])); });
  }

  function ent(path) {
    try { printInfo(getInfo(path)); }
    catch (e) { console.log('[ent] 错误: ' + errMsg(e)); }
  }

  ent.help = function () {
    console.log('[ent] Usage: ent([app_path])');
    console.log('       ent()                          current app entitlements');
    console.log('       ent("/path/to/App.app")        specified app bundle');
    console.log('       rpc.exports.entitlements()     return JSON');
  };

  var g = null;
  if (typeof globalThis !== 'undefined') g = globalThis;
  else if (typeof global !== 'undefined') g = global;
  else { try { g = Function('return this')(); } catch (e) { g = null; } }
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
    var cleanEnt = cleanExported(ent);
    g.ent = cleanEnt;
    g.entitlements = cleanEnt;
  }

  rpc.exports = {
    entitlements: function (path) {
      try { return getInfo(path); } catch (e) { return { error: errMsg(e) }; }
    }
  };

  if (g) {
    var reg = g.__fridaApi || (g.__fridaApi = { scripts: {} });
    reg.scripts.entitlements = ['ent()', 'entitlements()', 'ent.help()'];
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
