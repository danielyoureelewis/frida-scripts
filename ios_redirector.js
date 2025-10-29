// proxy_ios.js
// iOS-focused Frida proxy: rewrites IPv4 connects and higher-level CF/NSURLSession APIs
// Redirect target:
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

function tryNativeConnectHooks() {
    const candidates = ['connect', 'connect$NOCANCEL', 'connectat', 'sys_connect'];
    let attached = false;

    candidates.forEach(name => {
        try {
            const p = Module.findExportByName(null, name);
            if (p) {
                if (attachConnectExport(p, name)) attached = true;
            }
        } catch (e) {}
    });

    // enumerate modules and look for exports that contain "connect"
    if (!attached) {
        Process.enumerateModulesSync().forEach(m => {
            try {
                Module.enumerateExportsSync(m.name).forEach(exp => {
                    if (exp.name === 'connect' || exp.name.indexOf('connect') !== -1) {
                        if (attachConnectExport(exp.address, `${m.name}!${exp.name}`)) attached = true;
                    }
                });
            } catch (e) {}
        });
    }

    if (!attached) {
        console.log('No native connect exports found/attached.');
    }
    return attached;
}

// CFStream hook: CFStreamCreatePairWithSocketToHost(CFAllocatorRef, CFStringRef host, UInt32 port, CFReadStreamRef *readStream, CFWriteStreamRef *writeStream)
function tryCFStreamHook() {
    const names = ['CFStreamCreatePairWithSocketToHost', '_CFStreamCreatePairWithSocketToHost'];
    for (let name of names) {
        try {
            const addr = Module.findExportByName(null, name);
            if (!addr) continue;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    try {
                        // args[1] is CFStringRef host, args[2] is port (UInt32)
                        const hostPtr = args[1];
                        const port = args[2].toInt32();
                        // Attempt to read host string
                        let origHost = '<unknown>';
                        try {
                            if (!hostPtr.isNull()) origHost = ObjC.Object(hostPtr).toString();
                        } catch (e) {}
                        console.log(`[CFStream] original host=${origHost} port=${port}`);
                        // Replace host and port
                        try {
                            const newHost = ObjC.classes.CFStringCreateWithCString(null, TARGET_IP, 0); // kCFStringEncodingUTF8 = 0
                            args[1] = newHost;
                            args[2] = ptr(TARGET_PORT);
                            console.log(`[CFStream] redirected to ${TARGET_IP}:${TARGET_PORT}`);
                        } catch (e) {
                            // fallback: attempt to write pointer directly (not ideal)
                            console.warn('[CFStream] failed to replace CFString: ' + e);
                        }
                    } catch (e) {
                        // ignore
                    }
                }
            });
            console.log('Attached CFStream hook to ' + name + ' @ ' + addr);
            return true;
        } catch (e) {}
    }
    console.log('CFStreamCreatePairWithSocketToHost not found or hook failed.');
    return false;
}

// Objective-C: rewrite NSURLSession requests
function tryObjCHooks() {
    if (!ObjC.available) {
        console.log('ObjC runtime not available; skipping NSURLSession hooks.');
        return false;
    }
    try {
        const NSURL = ObjC.classes.NSURL;
        const NSURLRequest = ObjC.classes.NSURLRequest;
        const NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        const NSURLSession = ObjC.classes.NSURLSession;

        function makeLocalURLWithOriginal(origURLString) {
            try {
                // preserve path+query; replace host+port
                const urlObj = NSURL.URLWithString_(origURLString);
                if (urlObj === null) return null;
                const path = urlObj.path ? urlObj.path().toString() : '';
                const query = urlObj.query ? ('?' + urlObj.query().toString()) : '';
                const scheme = urlObj.scheme ? urlObj.scheme().toString() : 'http';
                const newUrlStr = scheme + "://" + TARGET_IP + ":" + TARGET_PORT + (path || '/') + (query || '');
                return NSURL.URLWithString_(newUrlStr);
            } catch (e) {
                return null;
            }
        }

        // helper to copy headers and method into mutable request
        function buildProxyRequest(origReq) {
            try {
                // origReq may be NSURLRequest or NSMutableURLRequest
                const origURL = origReq.URL ? origReq.URL().toString() : null;
                const newNSURL = makeLocalURLWithOriginal(origURL);
                if (!newNSURL) return origReq;

                const m = NSMutableURLRequest.alloc().initWithURL_(newNSURL);
                // copy method
                try {
                    const method = origReq.HTTPMethod ? origReq.HTTPMethod() : null;
                    if (method) m.setHTTPMethod_(method);
                } catch (e) {}
                // copy headers
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
                    // ensure Host header is original host (virtual hosting)
                    try {
                        const origHost = ObjC.Object(origReq.URL()).host();
                        if (origHost) m.setValue_forHTTPHeaderField_(origHost.toString(), "Host");
                    } catch (e) {}
                } catch (e) {}
                // copy body if present
                try {
                    const body = origReq.HTTPBody ? origReq.HTTPBody() : null;
                    if (body) m.setHTTPBody_(body);
                } catch (e) {}

                return m;
            } catch (e) {
                return origReq;
            }
        }

        // Hook -[NSURLSession dataTaskWithRequest:]
        try {
            const sel1 = "- dataTaskWithRequest:";
            if (NSURLSession[sel1]) {
                const origImpl = NSURLSession[sel1].implementation;
                NSURLSession[sel1].implementation = ObjC.implement(NSURLSession[sel1], function (handle, selector, req) {
                    try {
                        const objReq = ObjC.Object(req);
                        const newReq = buildProxyRequest(objReq);
                        return origImpl(handle, selector, newReq);
                    } catch (e) {
                        try { return origImpl(handle, selector, req); } catch (ee) { return ptr(0); }
                    }
                });
                console.log('Hooked NSURLSession ' + sel1);
            }
        } catch (e) {
            console.warn('Failed hooking dataTaskWithRequest: ' + e);
        }

        // Hook -[NSURLSession dataTaskWithURL:]
        try {
            const sel2 = "- dataTaskWithURL:";
            if (NSURLSession[sel2]) {
                const origImpl2 = NSURLSession[sel2].implementation;
                NSURLSession[sel2].implementation = ObjC.implement(NSURLSession[sel2], function (handle, selector, url) {
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
                console.log('Hooked NSURLSession ' + sel2);
            }
        } catch (e) {
            console.warn('Failed hooking dataTaskWithURL: ' + e);
        }

        // If the app uses NSURLConnection legacy APIs, hooking sendSynchronousRequest: or sendAsynchronousRequest: might be possible too.
        return true;
    } catch (e) {
        console.warn('ObjC hooks failed: ' + e);
        return false;
    }
}

setImmediate(function () {
    console.log('proxy_ios.js starting — redirecting traffic to ' + TARGET_IP + ':' + TARGET_PORT);
    const nativeOk = tryNativeConnectHooks();
    const cfOk = tryCFStreamHook();
    const objcOk = tryObjCHooks();

    if (!nativeOk && !cfOk && !objcOk) {
        console.log('No hooks installed (native / CF / ObjC). The app may be statically linked or using unusual networking code.');
        console.log('Consider adding hooks for sendto, send, socket, connectat, CFSocketConnectToAddress, or manually enumerating exports containing "connect" to attach to.');
    } else {
        console.log('Hooks installed (native=' + nativeOk + ', cf=' + cfOk + ', objc=' + objcOk + ').');
    }

    console.log('Note: on a physical iOS device, 127.0.0.1 points to the device itself. If you want to reach your Mac from the device, use a reverse tunnel (ssh -R) or set up a reachable host IP. On the iOS Simulator, 127.0.0.1 is the host machine.');
});
