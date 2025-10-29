// proxy_ios_no_findexport.js
// iOS Frida proxy WITHOUT Module.findExportByName usage.
// Redirects IPv4 connect destinations and higher-level CF/ObjC networking to TARGET_IP:TARGET_PORT.

'use strict';

const TARGET_IP = "127.0.0.1";
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
    const p = ip.split('.').map(n => parseInt(n,10) & 0xff);
    return ((p[0] << 24) >>> 0) | ((p[1] << 16) >>> 0) | ((p[2] << 8) >>> 0) | (p[3] >>> 0);
}
function readSockaddrIn(ptr) {
    try {
        const family = Memory.readU16(ptr);
        const portNet = Memory.readU16(ptr.add(2));
        const ipNet = Memory.readU32(ptr.add(4));
        const portHost = ((portNet & 0xff) << 8) | ((portNet >> 8) & 0xff);
        const b0 = (ipNet >>> 24) & 0xff;
        const b1 = (ipNet >>> 16) & 0xff;
        const b2 = (ipNet >>> 8) & 0xff;
        const b3 = (ipNet) & 0xff;
        return { family, ipStr: [b0,b1,b2,b3].join('.'), portHost };
    } catch (e) { return null; }
}

function attachConnectExport(ptr, label) {
    try {
        Interceptor.attach(ptr, {
            onEnter: function (args) {
                // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
                this.sockfd = args[0].toInt32();
                this.addr = args[1];
                try {
                    if (this.addr.isNull()) return;
                } catch (e) { return; }

                let family = 0;
                try { family = Memory.readU16(this.addr); } catch (e) { family = 0; }

                if (family === 2) { // AF_INET
                    const orig = readSockaddrIn(this.addr) || {};
                    console.log(`[${label}] fd=${this.sockfd} original -> ${orig.ipStr||'?'}:${orig.portHost||'?'}`);
                    const portNet = htons(TARGET_PORT);
                    const ipNet = ipToIntBE(TARGET_IP);
                    Memory.writeU16(this.addr.add(2), portNet);            // sin_port
                    Memory.writeU32(this.addr.add(4), htonl(ipNet));       // sin_addr (network order)
                    const after = readSockaddrIn(this.addr) || {};
                    console.log(`[${label}] fd=${this.sockfd} redirected -> ${after.ipStr||'?'}:${after.portHost||'?'}`);
                }
            }
        });
        console.log(`Attached to ${label} @ ${ptr}`);
        return true;
    } catch (e) {
        console.warn('attachConnectExport error for ' + label + ': ' + e);
        return false;
    }
}

// Find and attach to exported symbols whose names match any of the candidate substrings.
// DOES NOT call Module.findExportByName - uses Module.enumerateExportsSync only.
function scanAndAttachExports() {
    const candidateSubstrings = [
        'connect',          // connect, connect$NOCANCEL, connectat, sys_connect
        'connect$',
        'connectat',
        'sys_connect',
        'CFStreamCreatePairWithSocketToHost',
        'CFSocketConnectToAddress',
        'socket',           // socket / socketpair (we can attach to socket if desired)
        'sendto',
        'send',
        'recv',
        'accept',
        'accept4',
        'syscall'           // syscall entrypoint (may be present)
    ];

    const found = [];

    const mods = Process.enumerateModulesSync();
    mods.forEach(m => {
        let exports = [];
        try {
            exports = Module.enumerateExportsSync(m.name);
        } catch (e) {
            // some modules may not allow enumerating exports - skip them
            return;
        }
        exports.forEach(exp => {
            const nameLower = exp.name.toLowerCase();
            for (let sub of candidateSubstrings) {
                if (nameLower.indexOf(sub.toLowerCase()) !== -1) {
                    found.push({ module: m.name, name: exp.name, address: exp.address });
                    break;
                }
            }
        });
    });

    if (found.length === 0) {
        console.log('scanAndAttachExports: no matching exports found (no Module.findExportByName used).');
        return false;
    }

    // Attach to each reasonable candidate. Prefer exact connect-like names first.
    // Keep track if any connect-like were successfully attached.
    let attachedAny = false;
    // Try to attach to exports that look exactly like connect/connect$nocancel/connectat first
    const preferredOrder = ['connect$', 'connectat', 'sys_connect', 'connect', 'CFStreamCreatePairWithSocketToHost', 'CFSocketConnectToAddress'];
    // sort found by preference
    found.sort((a,b) => {
        const aIdx = preferredOrder.findIndex(x => a.name.indexOf(x) !== -1);
        const bIdx = preferredOrder.findIndex(x => b.name.indexOf(x) !== -1);
        return (aIdx === -1 ? 999 : aIdx) - (bIdx === -1 ? 999 : bIdx);
    });

    for (let entry of found) {
        const label = `${entry.module}!${entry.name}`;
        // conservative: only attach to symbols whose name looks like connect or CFStream or CFSocket
        const n = entry.name.toLowerCase();
        if (n === 'connect' || n.indexOf('connect') !== -1 || n.indexOf('cfstreamcreatepairwithsockettohost') !== -1 || n.indexOf('cfsocketconnecttoaddress') !== -1) {
            try {
                if (n.indexOf('cfstreamcreatepairwithsockettohost') !== -1 || n.indexOf('cfsocketconnecttoaddress') !== -1) {
                    // CFStream/CFSocket: we may want to intercept and rewrite args instead of sockaddr
                    try {
                        Interceptor.attach(entry.address, {
                            onEnter: function (args) {
                                try {
                                    // Best-effort: attempt to read CFString host at arg index 1
                                    const hostPtr = args[1];
                                    let origHost = '<unknown>';
                                    try {
                                        if (!hostPtr.isNull() && ObjC.available) {
                                            origHost = ObjC.Object(hostPtr).toString();
                                        }
                                    } catch (e) {}
                                    const port = args[2] ? args[2].toInt32() : -1;
                                    console.log(`[CF API ${label}] original host=${origHost} port=${port}`);
                                    // Replace host and port (best-effort): create CFString for target IP
                                    if (ObjC.available) {
                                        try {
                                            const cfNew = ObjC.classes.CFStringCreateWithCString(null, TARGET_IP, 0);
                                            args[1] = cfNew;
                                            args[2] = ptr(TARGET_PORT);
                                            console.log(`[CF API ${label}] redirected to ${TARGET_IP}:${TARGET_PORT}`);
                                        } catch (e) {
                                            // ignore replacement errors
                                        }
                                    }
                                } catch (e) {}
                            }
                        });
                        console.log(`Attached CF API hook to ${label}`);
                        attachedAny = true;
                    } catch (e) {
                        // skip
                    }
                } else {
                    // treat as connect-like native socket function: attempt sockaddr rewrite
                    if (attachConnectExport(entry.address, label)) attachedAny = true;
                }
            } catch (e) {
                // ignore attach failures
            }
        }
    }

    console.log(`scanAndAttachExports: scanned ${mods.length} modules, found ${found.length} candidate exports, attachedAny=${attachedAny}`);
    // print some of the matches for user visibility
    for (let i = 0; i < Math.min(found.length, 40); i++) {
        const f = found[i];
        console.log(`  match: ${f.module} -> ${f.name} @ ${f.address}`);
    }

    return attachedAny;
}

// ObjC NSURLSession hooks (higher-level)
function tryObjCHooks() {
    if (!ObjC.available) {
        console.log('ObjC not available; skipping ObjC hooks.');
        return false;
    }
    try {
        const NSURL = ObjC.classes.NSURL;
        const NSURLSession = ObjC.classes.NSURLSession;
        const NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;

        function makeLocalURLWithOriginal(origURLString) {
            try {
                const urlObj = NSURL.URLWithString_(origURLString);
                if (urlObj === null) return null;
                const path = urlObj.path ? urlObj.path().toString() : '';
                const query = urlObj.query ? ('?' + urlObj.query().toString()) : '';
                const scheme = urlObj.scheme ? urlObj.scheme().toString() : 'http';
                const newUrlStr = scheme + "://" + TARGET_IP + ":" + TARGET_PORT + (path || '/') + (query || '');
                return NSURL.URLWithString_(newUrlStr);
            } catch (e) { return null; }
        }

        function buildProxyRequest(origReq) {
            try {
                const origURL = origReq.URL ? origReq.URL().toString() : null;
                const newNSURL = makeLocalURLWithOriginal(origURL);
                if (!newNSURL) return origReq;

                const m = NSMutableURLRequest.alloc().initWithURL_(newNSURL);
                try {
                    const method = origReq.HTTPMethod ? origReq.HTTPMethod() : null;
                    if (method) m.setHTTPMethod_(method);
                } catch (e) {}
                try {
                    const headers = origReq.allHTTPHeaderFields ? origReq.allHTTPHeaderFields() : null;
                    if (headers) {
                        const keys = headers.allKeys();
                        for (let i = 0; i < keys.count(); i++) {
                            const k = keys.objectAtIndex_(i).toString();
                            const v = headers.objectForKey_(k).toString();
                            m.setValue_forHTTPHeaderField_(v, k);
                        }
                    }
                    try {
                        const origHost = ObjC.Object(origReq.URL()).host();
                        if (origHost) m.setValue_forHTTPHeaderField_(origHost.toString(), "Host");
                    } catch (e) {}
                } catch (e) {}
                try {
                    const body = origReq.HTTPBody ? origReq.HTTPBody() : null;
                    if (body) m.setHTTPBody_(body);
                } catch (e) {}

                return m;
            } catch (e) { return origReq; }
        }

        // Hook -[NSURLSession dataTaskWithRequest:]
        try {
            const selectorName = '- dataTaskWithRequest:';
            if (NSURLSession[selectorName]) {
                const origImpl = NSURLSession[selectorName].implementation;
                NSURLSession[selectorName].implementation = ObjC.implement(NSURLSession[selectorName], function (handle, selector, req) {
                    try {
                        const objReq = ObjC.Object(req);
                        const newReq = buildProxyRequest(objReq);
                        return origImpl(handle, selector, newReq);
                    } catch (e) {
                        try { return origImpl(handle, selector, req); } catch (ee) { return ptr(0); }
                    }
                });
                console.log('Hooked NSURLSession ' + selectorName);
            }
        } catch (e) { console.warn('Failed hooking dataTaskWithRequest: ' + e); }

        // Hook -[NSURLSession dataTaskWithURL:]
        try {
            const selectorName2 = '- dataTaskWithURL:';
            if (NSURLSession[selectorName2]) {
                const origImpl2 = NSURLSession[selectorName2].implementation;
                NSURLSession[selectorName2].implementation = ObjC.implement(NSURLSession[selectorName2], function (handle, selector, url) {
                    try {
                        const urlObj = ObjC.Object(url);
                        const urlStr = urlObj.absoluteString().toString();
                        const newNSURL = makeLocalURLWithOriginal(urlStr);
                        if (newNSURL) {
                            return origImpl2(handle, selector, newNSURL);
                        } else {
                            return origImpl2(handle, selector, url);
                        }
                    } catch (e) {
                        try { return origImpl2(handle, selector, url); } catch (ee) { return ptr(0); }
                    }
                });
                console.log('Hooked NSURLSession ' + selectorName2);
            }
        } catch (e) { console.warn('Failed hooking dataTaskWithURL: ' + e); }

        return true;
    } catch (e) {
        console.warn('ObjC hooks failed: ' + e);
        return false;
    }
}

setImmediate(function () {
    console.log('proxy_ios_no_findexport.js starting — targeting ' + TARGET_IP + ':' + TARGET_PORT);
    const attached = scanAndAttachExports();
    const objcOk = tryObjCHooks();

    if (!attached && !objcOk) {
        console.log('No native exports attached and ObjC hooks may not be active. The process might be using inlined syscalls or a custom networking stack.');
        console.log('If you want, I can add: memory-scan for syscall patterns, hooks for sendto/send/SSL functions, or block-level NSURLSession variants.');
    } else {
        console.log('Completed hooking stage: nativeAttached=' + attached + ' objcHooked=' + objcOk);
    }
    console.log('Note: on physical iOS device 127.0.0.1 is the device. Use a reachable host or tunnel to reach your laptop if needed.');
});
