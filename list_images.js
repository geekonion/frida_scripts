(function () {
function list_images(filter) {
    const modules = Process.enumerateModules();

    // 按基地址升序排序（低地址 -> 高地址）
    modules.sort((a, b) => a.base.compare(b.base));

    console.log(`[*] 共 ${modules.length} 个模块，按基地址升序排列:\n`);
    console.log('序号   基地址              大小        模块名');
    console.log('----   -----------------   ---------   ------------------------------');

    modules.forEach((m, i) => {
        const idx = String(i + 1).padStart(4, ' ');
        const base = m.base.toString().padEnd(17, ' ');
        const size = String(m.size).padEnd(9, ' ');
        console.log(`${idx}   ${base}   ${size}   ${m.path}`);
    });
}

list_images.help = function () {
    console.log('[list_images] Usage: list_images()');
    console.log('       list_images()   list loaded modules (sorted by base address)');
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
globalThis.list_images = cleanExported(list_images);

// ---- API 注册 ----
(function () {
    var g = (typeof globalThis !== 'undefined') ? globalThis :
            (typeof global !== 'undefined') ? global : null;
    if (!g) return;
    var reg = g.__fridaApi || (g.__fridaApi = { scripts: {} });
    reg.scripts.list_images = ['list_images()', 'list_images.help()'];
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
