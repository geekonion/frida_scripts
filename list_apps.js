// list_apps_filtered.js
// 用法: frida -U -l list_apps_filtered.js -f <任意App的Bundle ID>
// 加载后在 REPL 中调用: list_apps("user") / list_apps("system") / list_apps("encrypted") / list_apps("all")

'use strict';


(function () {
// ============================================================
// Mach-O 加壳检测（解析 LC_ENCRYPTION_INFO）
// ============================================================
const LC_ENCRYPTION_INFO      = 0x21;
const LC_ENCRYPTION_INFO_64   = 0x2C;

function isEncryptedBinary(filePath) {
    if (!filePath) return false;
    try {
        const bytes = File.readAllBytes(filePath);
        if (bytes.length < 28) return false;

        const magic = bytes.readU32();
        const is64 = (magic === 0xfeedfacf || magic === 0xcffaedfe);
        const headerSize = is64 ? 32 : 28;

        const ncmds = bytes.readU32(16);
        let offset = headerSize;

        for (let i = 0; i < ncmds; i++) {
            if (offset + 8 > bytes.length) break;
            const cmd = bytes.readU32(offset);
            const cmdsize = bytes.readU32(offset + 4);
            if (cmdsize === 0) break;

            if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
                // struct encryption_info_command (32-bit)
                //   uint32 cmd; uint32 cmdsize;
                //   uint32 cryptoff; uint32 cryptsize; uint32 cryptid;
                // 64-bit 版本多一个 uint32 pad
                const cryptidOffset = offset + 16; // cmd(4)+cmdsize(4)+cryptoff(4)+cryptsize(4) = 16
                if (cryptidOffset + 4 <= bytes.length) {
                    const cryptid = bytes.readU32(cryptidOffset);
                    return cryptid === 1; // 1 = 加密（有壳），0 = 未加密
                }
            }
            offset += cmdsize;
        }
        return false;
    } catch (e) {
        // 读取失败（如权限不足、路径不存在）时视为“未知”，返回 false 避免误报
        return false;
    }
}

// ============================================================
// 获取应用可执行文件路径
// ============================================================
function getExecutablePath(app) {
    if (!app) return null;
    // 优先使用 canonicalExecutablePath
    try {
        const p = app.canonicalExecutablePath();
        if (p && !p.isNull()) return p.toString();
    } catch (e) { /* 继续尝试其他方法 */ }

    // 回退到 bundleURL + 可执行文件名（通常与 .app 同名）
    try {
        const bundleURL = app.bundleURL();
        if (bundleURL && !bundleURL.isNull()) {
            const bundlePath = bundleURL.path().toString();
            const appName = bundlePath.split('/').pop().replace(/\.app$/, '');
            return bundlePath + '/' + appName;
        }
    } catch (e) { /* 忽略 */ }

    return null;
}

// ============================================================
// 核心枚举逻辑
// ============================================================
function collectAllApps() {
    const result = [];
    if (!ObjC.available) return result;

    const workspace = ObjC.classes.LSApplicationWorkspace.defaultWorkspace();
    if (!workspace) return result;

    const applications = workspace.allApplications();
    if (!applications) return result;

    const enumerator = applications.objectEnumerator();
    let app;
    while ((app = enumerator.nextObject()) !== null) {
        try {
            const bundleId = app.applicationIdentifier()
                ? app.applicationIdentifier().toString()
                : '(unknown)';
            const name = app.localizedName()
                ? app.localizedName().toString()
                : '(no name)';

            let appType = 'Unknown';
            try {
                const t = app.applicationType();
                if (t) appType = t.toString(); // "User" 或 "System"
            } catch (e) { /* 部分应用可能没有此属性 */ }

            const execPath = getExecutablePath(app);
            const encrypted = execPath ? isEncryptedBinary(execPath) : false;

            result.push({
                bundleId: bundleId,
                name: name,
                type: appType,
                encrypted: encrypted,
                execPath: execPath || '(unavailable)'
            });
        } catch (e) {
            // 单个应用读取失败，跳过
        }
    }
    return result;
}

// ============================================================
// 输出格式化
// ============================================================
function printApps(apps, label) {
    apps = Array.isArray(apps) ? apps : [];
    label = label || '应用列表';
    console.log(`\n===== ${label} (共 ${apps.length} 个) =====\n`);
    console.log(
        '类型'.padEnd(8, ' ') +
        '加壳'.padEnd(6, ' ') +
        'Bundle ID'.padEnd(45, ' ') +
        '显示名称'
    );
    console.log('-'.repeat(8) + '  ' + '-'.repeat(6) + '  ' + '-'.repeat(45) + '  ' + '-'.repeat(30));

    apps.sort((a, b) => String(a && a.bundleId || '').localeCompare(String(b && b.bundleId || ''))).forEach(app => {
        app = app || {};
        const typeLabel = String(app.type || 'Unknown').padEnd(8, ' ');
        const encLabel = (app.encrypted ? '有壳' : '无壳').padEnd(6, ' ');
        const id = String(app.bundleId || '').padEnd(45, ' ');
        console.log(`${typeLabel}  ${encLabel}  ${id}  ${app.name || ''}`);
    });
}

// ============================================================
// 暴露给 REPL 的过滤函数
// ============================================================
function list_apps(filter) {
    const all = collectAllApps();
    if (all.length === 0) {
        console.log('[!] 未获取到应用列表（请确认目标进程已加载 MobileCoreServices）');
        return;
    }

    let filtered;
    let label;

    switch ((filter || 'all').toLowerCase()) {
        case 'user':
        case '用户':
            filtered = all.filter(a => a.type === 'User');
            label = '用户应用';
            break;

        case 'system':
        case '系统':
            filtered = all.filter(a => a.type === 'System');
            label = '系统应用';
            break;

        case 'encrypted':
        case '有壳':
            filtered = all.filter(a => a.encrypted === true);
            label = '有壳（加密）应用';
            break;

        case 'decrypted':
        case '无壳':
            filtered = all.filter(a => a.encrypted === false && a.type === 'User');
            label = '无壳（用户）应用';
            break;

        case 'all':
        case '全部':
        default:
            filtered = all;
            label = '全部应用';
            break;
    }

    printApps(filtered, label);
    return filtered; // 方便进一步在 REPL 中处理
}

// 链式调用：list_apps.user() / .system() / .encrypted() / .decrypted()
list_apps.all = function () { return list_apps('all'); };
list_apps.user = function () { return list_apps('user'); };
list_apps.system = function () { return list_apps('system'); };
list_apps.encrypted = function () { return list_apps('encrypted'); };
list_apps.decrypted = function () { return list_apps('decrypted'); };

list_apps.help = function () {
    console.log('[list_apps] Usage: list_apps()');
    console.log('       list_apps()             all apps');
    console.log('       list_apps.all()         all apps');
    console.log('       list_apps.user()        user apps only');
    console.log('       list_apps.system()      system apps only');
    console.log('       list_apps.encrypted()   encrypted (packed) apps');
    console.log('       list_apps.decrypted()   decrypted user apps');
};

// 清洗函数对象：只保留自定义方法，屏蔽 apply/call/bind 等内置属性出现在 REPL 补全
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

// 暴露到全局：清洗后的对象，补全里只有真实方法
globalThis.list_apps = cleanExported(list_apps);

// ---- API 注册 ----
(function () {
    var g = (typeof globalThis !== 'undefined') ? globalThis :
            (typeof global !== 'undefined') ? global : null;
    if (!g) return;
    var reg = g.__fridaApi || (g.__fridaApi = { scripts: {} });
    reg.scripts.list_apps = [
        'list_apps()',
        'list_apps.all()',
        'list_apps.user()',
        'list_apps.system()',
        'list_apps.encrypted()',
        'list_apps.decrypted()',
        'list_apps.help()'
    ];
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
