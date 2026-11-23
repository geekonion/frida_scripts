// enumerate_env.js
// 兼容 Frida 17+ 及更早版本的环境变量枚举脚本
'use strict';


(function () {
// ============================================================
// API 兼容层：跨 Frida 版本查找全局导出符号
// - Frida 17+ : Module.getGlobalExportByName / Module.findGlobalExportByName
// - Frida <=16: Module.findExportByName(null, name)
// ============================================================
function findGlobalExport(name) {
    if (!name) return null;
    if (typeof Module.getGlobalExportByName === 'function') {
        try {
            const p = Module.getGlobalExportByName(name);
            if (p) return p;
        } catch (e) { /* 继续尝试下一个 */ }
    }
    if (typeof Module.findGlobalExportByName === 'function') {
        try {
            const p = Module.findGlobalExportByName(name);
            if (p) return p;
        } catch (e) { /* 继续尝试下一个 */ }
    }
    if (typeof Module.findExportByName === 'function') {
        try {
            const p = Module.findExportByName(null, name);
            if (p) return p;
        } catch (e) { /* 继续 */ }
    }
    return null;
}

// ============================================================
// 取 char ** environ 的两种方式
// ============================================================

function getEnvironViaNsGetEnviron() {
    const addr = findGlobalExport('_NSGetEnviron');
    if (!addr) return null;

    let fn;
    try {
        fn = new NativeFunction(addr, 'pointer', []);
    } catch (e) {
        console.log(`[-] 创建 _NSGetEnviron NativeFunction 失败: ${e}`);
        return null;
    }
    if (typeof fn !== 'function') {
        console.log('[-] _NSGetEnviron 未能创建为可调用对象');
        return null;
    }

    try {
        // _NSGetEnviron() 返回 char ***，解引用一次得到 char **
        const ptr = fn();
        if (!ptr || ptr.isNull()) return null;
        return ptr.readPointer();
    } catch (e) {
        console.log(`[-] 调用 _NSGetEnviron 失败: ${e}`);
        return null;
    }
}

function getEnvironViaSymbol() {
    const sym = findGlobalExport('environ');
    if (!sym) return null;
    try {
        // environ 符号地址处存放的就是 char **
        return sym.readPointer();
    } catch (e) {
        console.log(`[-] 读取 environ 符号失败: ${e}`);
        return null;
    }
}

// ============================================================
// 遍历 char **（以 NULL 结尾的字符串数组）
// ============================================================
function readCStringArray(charPtrPtr) {
    const result = [];
    if (!charPtrPtr || charPtrPtr.isNull()) return result;

    const ptrSize = Process.pointerSize;
    const MAX = 100000; // 安全阀，防止野指针导致死循环

    for (let i = 0; i < MAX; i++) {
        let entryPtr;
        try {
            entryPtr = charPtrPtr.add(i * ptrSize).readPointer();
        } catch (e) {
            break;
        }
        if (entryPtr.isNull()) break;

        try {
            result.push(entryPtr.readUtf8String());
        } catch (e) {
            result.push(`<read error @ index ${i}: ${e}>`);
        }
    }
    return result;
}

// ============================================================
// ObjC 兜底方案
// ============================================================
function getEnvironViaNSProcessInfo() {
    if (!ObjC.available) return null;
    try {
        const dict = ObjC.classes.NSProcessInfo.processInfo().environment();
        const keys = dict.allKeys();
        const count = keys.count();
        const out = [];
        for (let i = 0; i < count; i++) {
            const k = keys.objectAtIndex_(i);
            const v = dict.objectForKey_(k);
            out.push(`${k.toString()}=${v.toString()}`);
        }
        return out;
    } catch (e) {
        console.log(`[!] NSProcessInfo 读取失败: ${e}`);
        return null;
    }
}

// ============================================================
// 输出
// ============================================================
function printEnvList(label, list) {
    label = label || '环境变量';
    list = Array.isArray(list) ? list : [];
    console.log(`\n===== ${label} (共 ${list.length} 条) =====\n`);
    list.slice().sort().forEach((item, i) => {
        console.log(`${String(i + 1).padStart(4, ' ')}  ${item}`);
    });
}

// ============================================================
// 主流程
// ============================================================
function main() {
    console.log(`[*] 平台: ${Process.platform}  架构: ${Process.arch}  PID: ${Process.id}`);

    let envList = null;
    let source = '';

    // 路径 1：_NSGetEnviron()
    let ptr = getEnvironViaNsGetEnviron();
    if (ptr) {
        envList = readCStringArray(ptr);
        source = '_NSGetEnviron()';
    }

    // 路径 2：environ 全局符号
    if (!envList || envList.length === 0) {
        ptr = getEnvironViaSymbol();
        if (ptr) {
            envList = readCStringArray(ptr);
            source = 'environ 符号';
        }
    }

    // 路径 3：ObjC NSProcessInfo
    if ((!envList || envList.length === 0) && ObjC.available) {
        const list = getEnvironViaNSProcessInfo();
        if (list) {
            envList = list;
            source = 'NSProcessInfo.environment';
        }
    }

    if (envList && envList.length > 0) {
        printEnvList(`环境变量 (via ${source})`, envList);
    } else {
        console.log('[!] 未能获取到环境变量');
    }
}

main.help = function () {
    console.log('[list_envs] Usage: list_envs()');
    console.log('       list_envs()   print process environment variables');
};

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

// 暴露到全局：清洗后补全里只有真实方法
globalThis.list_envs = cleanExported(main);

// ---- API 注册 ----
(function () {
    var g = (typeof globalThis !== 'undefined') ? globalThis :
            (typeof global !== 'undefined') ? global : null;
    if (!g) return;
    var reg = g.__fridaApi || (g.__fridaApi = { scripts: {} });
    reg.scripts.list_envs = ['list_envs()', 'list_envs.help()'];
    if (!g.api) {
        g.api = function () {
            var r = g.__fridaApi || { scripts: {} };
            console.log('[api] 已加载脚本的公开函数：');
            Object.keys(r.scripts).sort().forEach(function (n) {
                console.log('  ' + n + ': ' + r.scripts[n].join(', '));
            });
        };
    }
})();

})();
