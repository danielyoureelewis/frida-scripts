// proxy.js
// Usage: frida -U -f <package.or.binary> -l proxy.js --no-pause
// Rewrites IPv4 connect() destinations to 127.0.0.1:8080

'use strict';

const TARGET_IP = '127.0.0.1';
const TARGET_PORT = 8080;

function htons(x) {
    return ((x & 0xff) << 8) | ((x >> 8) & 0xff);
}
function htonl(x) {
    return ((x & 0xff) << 24) |
           ((x & 0xff00) << 8) |
           ((x >> 8) & 0xff00) |
           ((x >> 24) & 0xff);
}
function ipToIntBE(ip) {
    const parts = ip.split('.').map(function (p) { return parseInt(p, 10) & 0xff; });
    return ((parts[0] << 24) >>> 0) | ((parts[1] << 16) >>> 0) | ((parts[2] << 8) >>> 0) | (parts[3] >>> 0);
}

function readSockaddrIn(ptrSockaddr, addrlen) {
    // sockaddr_in struct layout (IPv4)
    // uint16_t sin_family;   // offset 0
    // uint16_t sin_port;     // offset 2 (network order)
    // struct in_addr sin_addr; // offset 4 (network order uint32)
    try {
        const family = Memory.readU16(ptrSockaddr); // native-endian read
        const portNet = Memory.readU16(ptrSockaddr.add(2));
        const ipNet = Memory.readU32(ptrSockaddr.add(4));
        // convert net-order values to host-order for readable logging:
        const portHost = ((portNet & 0xff) << 8) | ((portNet >> 8) & 0xff);
        // ipNet is big-endian (network). Convert to dotted:
        const b0 = (ipNet >>> 24) & 0xff;
        const b1 = (ipNet >>> 16) & 0xff;
        const b2 = (ipNet >>> 8) & 0xff;
        const b3 = (ipNet) & 0xff;
        const ipStr = [b0,b1,b2,b3].join('.');
        return { family: family, portHost: portHost, ipStr: ipStr };
    } catch (e) {
        return null;
    }
}

const connectPtr = Module.findExportByName(null, 'connect');
if (!connectPtr) {
    console.error('connect() symbol not found on this platform');
} else {
    console.log('hooking connect at', connectPtr);
    Interceptor.attach(connectPtr, {
        onEnter: function (args) {
            // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
            this.sockfd = args[0].toInt32();
            this.addr = args[1];
            this.addrlen = args[2].toInt32();

            if (this.addr.isNull()) {
                return;
            }

            // read family
            try {
                const family = Memory.readU16(this.addr);
                // AF_INET is usually 2
                if (family === 2) {
                    const orig = readSockaddrIn(this.addr, this.addrlen);
                    if (orig) {
                        console.log('[connect] fd=' + this.sockfd + ' original -> ' + orig.ipStr + ':' + orig.portHost);
                    } else {
                        console.log('[connect] fd=' + this.sockfd + ' original -> <unreadable sockaddr_in>');
                    }

                    // overwrite port (network order) and ip (network order)
                    const portNet = htons(TARGET_PORT);          // produce bytes [0x1F,0x90] for 8080
                    const ipNet = ipToIntBE(TARGET_IP);         // 0x7f000001 for 127.0.0.1
                    // Write network-order values so the kernel sees the right address
                    Memory.writeU16(this.addr.add(2), portNet);
                    Memory.writeU32(this.addr.add(4), htonl(ipNet)); // ensure big-endian value is stored correctly

                    const after = readSockaddrIn(this.addr, this.addrlen);
                    if (after) {
                        console.log('[connect] fd=' + this.sockfd + ' redirected -> ' + after.ipStr + ':' + after.portHost);
                    } else {
                        console.log('[connect] fd=' + this.sockfd + ' redirected -> <unreadable sockaddr_in>');
                    }
                } else {
                    // Not AF_INET — leave alone
                    // (Optionally handle AF_INET6 if you need IPv6.)
                }
            } catch (e) {
                // Defensive logging; don't break the process
                console.warn('error handling connect hook:', e);
            }
        },
        onLeave: function (retval) {
            // optional: log results
            // console.log('connect returned', retval.toInt32());
        }
    });
}
