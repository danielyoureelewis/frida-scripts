// proxy_nomod.js
// Frida 17 friendly — avoids Module.* entirely.
// Rewrites IPv4 connect() destinations to 127.0.0.1:8080
// Usage: frida -U -f <package.or.binary> -l proxy_nomod.js --no-pause

'use strict';

// --- Target redirect ---
const TARGET_IP = '127.0.0.1';
const TARGET_PORT = 8080;

// --- Helpers (no Module usage) ---
function ipToBytes(ip) {
    return ip.split('.').map(p => parseInt(p, 10) & 0xff);
}
function portToBytes(port) {
    return [(port >> 8) & 0xff, port & 0xff];
}

function readSockaddrIn(ptrSockaddr) {
    try {
        const family = Memory.readU16(ptrSockaddr);
        const ph = Memory.readU8(ptrSockaddr.add(2));
        const pl = Memory.readU8(ptrSockaddr.add(3));
        const portHost = (ph << 8) | pl;
        const b0 = Memory.readU8(ptrSockaddr.add(4));
        const b1 = Memory.readU8(ptrSockaddr.add(5));
        const b2 = Memory.readU8(ptrSockaddr.add(6));
        const b3 = Memory.readU8(ptrSockaddr.add(7));
        const ipStr = [b0,b1,b2,b3].join('.');
        return { family: family, ipStr: ipStr, portHost: portHost };
    } catch (e) {
        return null;
    }
}

function writeSockaddrIn(ptrSockaddr, ipStr, port) {
    const portBytes = portToBytes(port);
    const ipBytes = ipToBytes(ipStr);
    const combined = [portBytes[0], portBytes[1], ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]];
    Memory.writeByteArray(ptrSockaddr.add(2), combined);
}

// --- Connect symbol discovery WITHOUT Module ---
function findConnectAddressesNoModule() {
    const found = [];

    // 1) Try DebugSymbol.findFunctionsMatching() for "connect" (broad search).
    // It returns array of symbol names matching the pattern when symbols are available.
    try {
        const matches = DebugSymbol.findFunctionsMatching('connect');
        if (matches && matches.length) {
            for (let m of matches) {
                // m may be a string like "module!symbol" or just symbol name depending on platform.
                try {
                    const ds = DebugSymbol.fromName(m);
                    if (ds && ds.address) {
                        const addr = ds.address;
                        // Avoid duplicates
                        if (!found.some(x => x.equals(addr))) {
                            found.push(addr);
                            console.log('[finder-debug] found symbol via findFunctionsMatching ->', m, addr);
                        }
                    }
                } catch (e) {
                    // ignore individual failures
                }
            }
        } else {
            console.log('[finder-debug] DebugSymbol.findFunctionsMatching("connect") returned no matches.');
        }
    } catch (e) {
        console.warn('[finder-debug] findFunctionsMatching failed or unsupported:', e);
    }

    // 2) Try direct DebugSymbol.fromName for common variants
    const variants = ['connect', '_connect', '__connect', 'connect$imp', 'connect@plt'];
    for (let name of variants) {
        try {
            const ds = DebugSymbol.fromName(name);
            if (ds && ds.address) {
                const addr = ds.address;
                if (!found.some(x => x.equals(addr))) {
                    found.push(addr);
                    console.log('[finder-debug] found symbol via fromName ->', name, addr);
                }
            }
        } catch (e) {
            // fromName can throw if symbol missing; ignore
        }
    }

    // 3) If still nothing, try searching exported function names visible via DebugSymbol.enumerateSymbols ?
    // (Some platforms support DebugSymbol.enumerateSymbols, but it can be noisy — try it defensively)
    try {
        if (typeof DebugSymbol.enumerateSymbols === 'function') {
            const all = DebugSymbol.enumerateSymbols();
            for (let s of all) {
                if (s && s.name && s.name.indexOf('connect') !== -1) {
                    try {
                        const ds = DebugSymbol.fromName(s.name);
                        if (ds && ds.address && !found.some(x => x.equals(ds.address))) {
                            found.push(ds.address);
                            console.log('[finder-debug] found symbol via enumerateSymbols ->', s.name, ds.address);
                        }
                    } catch (e) {
                        // ignore
                    }
                }
            }
        }
    } catch (e) {
        // ignore enumerateSymbols failures
    }

    return found;
}

// --- Attach interceptor to addresses found ---
function attachToConnectAddrs(addrs) {
    if (!addrs || addrs.length === 0) {
        console.error('[attach] no connect addresses found (no Module usage).');
        return false;
    }

    for (let addr of addrs) {
        try {
            console.log('[attach] attaching to connect at', addr);
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
                    this.sockfd = args[0].toInt32();
                    this.addr = args[1];
                    this.addrlen = args[2] ? args[2].toInt32() : 0;

                    if (!this.addr || this.addr.isNull()) {
                        return;
                    }

                    let family;
                    try {
                        family = Memory.readU16(this.addr);
                    } catch (e) {
                        console.warn('[connect-hook] unreadable sockaddr family:', e);
                        return;
                    }

                    if (family === 2) { // AF_INET
                        const orig = readSockaddrIn(this.addr);
                        if (orig) {
                            console.log('[connect] fd=' + this.sockfd + ' original -> ' + orig.ipStr + ':' + orig.portHost);
                        } else {
                            console.log('[connect] fd=' + this.sockfd + ' original -> <unreadable sockaddr_in>');
                        }

                        try {
                            writeSockaddrIn(this.addr, TARGET_IP, TARGET_PORT);
                            const after = readSockaddrIn(this.addr);
                            if (after) {
                                console.log('[connect] fd=' + this.sockfd + ' redirected -> ' + after.ipStr + ':' + after.portHost);
                            } else {
                                console.log('[connect] fd=' + this.sockfd + ' redirected -> <unreadable sockaddr_in>');
                            }
                        } catch (e) {
                            console.warn('[connect-hook] error writing redirected sockaddr:', e);
                        }
                    } else {
                        // leave non-AF_INET alone
                    }
                },
                onLeave: function (retval) {
                    // optional: log return value or errors
                    // console.log('connect returned', retval.toInt32());
                }
            });
        } catch (e) {
            console.warn('[attach] failed to attach to', addr, e);
        }
    }

    return true;
}

// --- Main flow ---
try {
    const addrs = findConnectAddressesNoModule();
    if (!addrs || addrs.length === 0) {
        // no addresses found via DebugSymbol — give a helpful message but do not use Module
        console.error('\n[fatal] Could not locate connect() using DebugSymbol methods.\n' +
                      'Possible reasons:\n' +
                      ' - Binary is stripped and does not expose symbols\n' +
                      ' - connect is inlined or resolved via PLT/IMPs not present in debug symbols\n' +
                      'Fallback suggestions (I can provide these hooks without using Module):\n' +
                      '  * Hook Java Socket.connect / OkHttp native methods (if the app is Java/Android).\n' +
                      '  * Hook Objective-C NSURLSession/CFStream APIs on iOS.\n' +
                      '  * Hook sendto / socket as alternative native-level hooks.\n' +
                      'If you want one of those fallbacks, tell me which and I will add it (still without using Module).\n');
    } else {
        const ok = attachToConnectAddrs(addrs);
        if (ok) {
            console.log('[main] attach complete. Intercepting connect() and redirecting IPv4 to ' + TARGET_IP + ':' + TARGET_PORT);
        } else {
            console.error('[main] attach failed for discovered addresses.');
        }
    }
} catch (e) {
    console.error('[main] unexpected error:', e);
}
