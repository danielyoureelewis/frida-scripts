// proxy.js
// Frida script (Frida 17 safe) that rewrites IPv4 connect() destinations to 127.0.0.1:8080
// Usage: frida -U -f <package.or.binary> -l proxy.js --no-pause

'use strict';

// Target redirect
const TARGET_IP = '127.0.0.1';
const TARGET_PORT = 8080;

// ---------- Helpers ----------
function ipToBytes(ip) {
    return ip.split('.').map(p => parseInt(p, 10) & 0xff);
}
function portToBytes(port) {
    // network order (big-endian)
    return [(port >> 8) & 0xff, port & 0xff];
}

// Read sockaddr_in (IPv4) for logging
function readSockaddrIn(ptrSockaddr) {
    try {
        const family = Memory.readU16(ptrSockaddr);
        // read port bytes individually (network order)
        const portHigh = Memory.readU8(ptrSockaddr.add(2));
        const portLow  = Memory.readU8(ptrSockaddr.add(3));
        const portHost = (portHigh << 8) | portLow;
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

// Write sockaddr_in (overwrite port and IPv4 address) using explicit bytes to avoid endianness pitfalls
function writeSockaddrIn(ptrSockaddr, ipStr, port) {
    const portBytes = portToBytes(port);
    const ipBytes = ipToBytes(ipStr);
    // Write port (2 bytes) followed by ip (4 bytes) starting at offset 2
    const combined = [portBytes[0], portBytes[1], ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]];
    Memory.writeByteArray(ptrSockaddr.add(2), combined);
}

// ---------- Robust connect symbol finder (Frida 17 safe) ----------
function findConnectSymbol() {
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

    // Full-scan fallback: enumerate modules and their exports (slower, but robust)
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
        console.warn('[finder] full-scan failed:', e);
    }

    console.error('[finder] connect() symbol not found');
    return null;
}

// ---------- Hook connect() ----------
const connectPtr = findConnectSymbol();
if (!connectPtr) {
    // If you prefer not to abort, comment the next line and proceed with alternative hooks (e.g., sendto, socket, Java Socket#connect)
    throw new Error('connect() symbol not found — aborting hook');
}

console.log('Hooking connect at', connectPtr);

Interceptor.attach(connectPtr, {
    onEnter: function (args) {
        // signature: int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        this.sockfd = args[0].toInt32();
        this.addr = args[1];
        this.addrlen = args[2].toInt32();

        if (this.addr.isNull()) {
            return;
        }

        // read family (uint16_t at offset 0)
        let family;
        try {
            family = Memory.readU16(this.addr);
        } catch (e) {
            console.warn('[connect-hook] unreadable sockaddr family:', e);
            return;
        }

        // AF_INET typically equals 2 on most platforms
        if (family === 2) {
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
            // Not AF_INET; leave alone. (If you need AF_INET6 add handling for sockaddr_in6.)
        }
    },
    onLeave: function (retval) {
        // optional: log result
        // console.log('connect returned', retval.toInt32());
    }
});
