// Robust cross-platform find for the `connect` symbol (Frida 17 safe)
function findConnectSymbol() {
    // First try common libc names per platform (fast path)
    const commonLibs = {
        'android': ['libc.so'],
        'linux':   ['libc.so.6','libc.so'],
        'darwin':  ['libSystem.B.dylib','libSystem.dylib','libSystem'],
        'ios':     ['libSystem.B.dylib','libSystem.dylib','libSystem'],
        'windows': ['Ws2_32.dll','ws2_32.dll','msvcrt.dll']
    }[Process.platform] || ['libc.so'];

    for (let name of commonLibs) {
        try {
            const addr = Module.findExportByName(name, 'connect');
            if (addr) {
                console.log('[finder] connect found in', name, '->', addr);
                return addr;
            }
        } catch (e) {
            // ignore
        }
    }

    // Full scan fallback: enumerate modules and their exports (slower but reliable)
    try {
        const mods = Module.enumerateModulesSync();
        for (let m of mods) {
            try {
                const exps = Module.enumerateExportsSync(m.name);
                for (let e of exps) {
                    if (e.name === 'connect') {
                        console.log('[finder] connect found in', m.name, '->', e.address);
                        return e.address;
                    }
                }
            } catch (e) {
                // ignore modules we can't inspect
            }
        }
    } catch (e) {
        // final fallback
        console.warn('[finder] full-scan failed:', e);
    }

    console.error('[finder] connect() symbol not found');
    return null;
}

const connectPtr = findConnectSymbol();
if (!connectPtr) {
    throw new Error('connect() symbol not found — aborting hook');
}
