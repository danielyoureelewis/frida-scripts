/**
 * iOS Traffic Redirection and SSL Pinning Bypass Frida Script
 *
 * This script hooks the low-level 'connect' function and also hooks the
 * certificate trust evaluation process to bypass SSL/Certificate pinning.
 *
 * Proxy Target: 127.0.0.1:8080
 *
 * Usage: frida -U -f <BUNDLE_ID> -l traffic_redirector.js --no-pause
 *
 * NOTE: Updated for Frida 17+ compatibility and SSL Pinning bypass.
 */

// --- Configuration ---
const PROXY_IP = "127.0.0.1";
const PROXY_PORT = 8080;
const K_SEC_TRUST_RESULT_PROCEED = 1; // Constant for forced success

// Convert IP string (e.g., "127.0.0.1") to its network byte order 32-bit integer (e.g., 0x7F000001)
function ipToNetworkByteOrder(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) {
        throw new Error("Invalid IPv4 address format.");
    }
    // Convert to Big-Endian (Network Byte Order)
    return (parseInt(parts[0], 10) << 24 |
            parseInt(parts[1], 10) << 16 |
            parseInt(parts[2], 10) << 8 |
            parseInt(parts[3], 10)) >>> 0;
}

// Convert port (host byte order) to network byte order (Big-Endian)
function portToNetworkByteOrder(port) {
    return (port >> 8) | (port << 8) & 0xFFFF;
}

/**
 * Hooks SecTrustEvaluate and forces it to return success (kSecTrustResultProceed).
 * This is the most common way to bypass SSL pinning on iOS.
 */
function sslPinningBypass() {
    // SecTrustEvaluate is in Security.framework
    const secTrustEvaluatePtr = Module.findExportByName("Security.framework", "SecTrustEvaluate");

    if (secTrustEvaluatePtr) {
        console.log("[+] Found SecTrustEvaluate. Applying SSL Pinning bypass hook...");
        
        Interceptor.attach(secTrustEvaluatePtr, {
            onLeave: function(retval) {
                // The function signature is OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result);
                // retval is the OSStatus, which should be 0 (errSecSuccess)
                retval.replace(0); 
                
                // args[1] is the pointer to the result (SecTrustResultType *result)
                // In Frida's hook context, the second argument (SecTrustResultType *) is usually x1 on arm64
                const resultPtr = this.context.x1; 
                
                if (resultPtr && !resultPtr.isNull()) {
                    // Write kSecTrustResultProceed (1) to the result pointer, forcing the trust check to pass.
                    resultPtr.writeU32(K_SEC_TRUST_RESULT_PROCEED);
                    console.log("[<<<] SecTrustEvaluate bypassed (forced kSecTrustResultProceed).");
                }
            }
        });
        return true;
    } else {
        console.warn("[-] Could not find SecTrustEvaluate. SSL pinning bypass may be incomplete for this app.");
        return false;
    }
}


// --- Main Hooking Logic ---
try {
    // --- FRIDA 17+ COMPATIBILITY FIX: Locate connect ---
    const libSystem = Process.getModuleByName("libSystem.B.dylib");

    let connectPtr = null;
    if (libSystem) {
        connectPtr = libSystem.findExportByName("connect");
    }
    // ------------------------------------

    // EXECUTE THE SSL BYPASS FUNCTION (always attempt to apply the bypass)
    const bypassApplied = sslPinningBypass();

    if (connectPtr) {
        // If 'connect' pointer is found, proceed with traffic redirection hook
        console.log(`[+] Found connect at ${connectPtr}`);

        const newIP_NBO = ipToNetworkByteOrder(PROXY_IP);
        const newPort_NBO = portToNetworkByteOrder(PROXY_PORT);

        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                try {
                    // The connect function signature is: int connect(int socket, const struct sockaddr *address, socklen_t address_len);
                    const addr = args[1];

                    if (addr.isNull()) {
                        return;
                    }

                    // 2. Read the address family (sa_family) from the sockaddr structure.
                    const sa_family = addr.add(1).readU8(); // AF_INET is 2, AF_INET6 is 30

                    // Only intercept IPv4 connections (AF_INET = 2)
                    if (sa_family === 2) {
                        const originalPort = addr.add(2).readU16();
                        const originalIP = addr.add(4).readU32();

                        // Convert Network Byte Order (NBO) values back to human-readable strings for logging
                        const originalPortHost = (originalPort >> 8) | (originalPort << 8) & 0xFFFF;
                        const originalIPStr = [
                            (originalIP >> 24) & 0xFF,
                            (originalIP >> 16) & 0xFF,
                            (originalIP >> 8) & 0xFF,
                            originalIP & 0xFF
                        ].join('.');

                        console.log(`[***] Intercepting connection to ${originalIPStr}:${originalPortHost}...`);

                        // 3. Overwrite the destination address to the proxy (127.0.0.1:8080)
                        addr.add(2).writeU16(newPort_NBO);
                        addr.add(4).writeU32(newIP_NBO);

                        console.log(`[<<<] Redirected to ${PROXY_IP}:${PROXY_PORT}`);
                    }
                } catch (e) {
                    // Enhanced error logging: log the error and the native stack trace
                    console.error(`[!!!] Error inside connect hook onEnter: ${e.message}`);
                    console.error(`[!!!] Backtrace (Native):`);
                    
                    console.error(Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n'));
                }
            },
            onLeave: function (retval) {
                // No changes here
            }
        });

        console.log(`[+] Frida script loaded successfully. Traffic redirection is active. SSL bypass status: ${bypassApplied ? 'Active' : 'Warning'}.`);

    } else {
        // If 'connect' pointer is NOT found, log the failure but note the SSL bypass status
        console.error("[-] Traffic redirection is DISABLED because 'connect' function could not be located in libSystem.B.dylib.");
        console.log(`[!] Script loaded. SSL bypass status: ${bypassApplied ? 'Active' : 'Warning'}.`);
    }

} catch (e) {
    // Log errors during script initialization
    console.error(`[-] A critical error occurred during script initialization: ${e.message}`);
}
