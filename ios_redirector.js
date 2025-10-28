/**
 * iOS Traffic Redirection and UNIVERSAL SSL Pinning Bypass Frida Script
 *
 * This version uses the most aggressive bypass techniques by hooking low-level
 * SSL functions (SSLSetSessionOption and SSLCopyPeerTrust) to disable pinning
 * checks at the core networking library level, in addition to the connect hook.
 *
 * Proxy Target: 127.0.0.1:8080
 *
 * Usage: frida -U -f <BUNDLE_ID> -l traffic_redirector.js --no-pause
 *
 * NOTE: Updated for Frida 17+ compatibility.
 */

// --- Configuration ---
const PROXY_IP = "127.0.0.1";
const PROXY_PORT = 8080;
// Constant for forced successful trust result
const K_SEC_TRUST_RESULT_PROCEED = 1; 
const K_SSL_SESSION_OPTION_DISABLE_CERT_VERIFICATION = 6;


// --- Utility Functions ---

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
    // We write a U16 in Host-Endian and let Frida handle the system's memory layout.
    return (port >> 8) | (port << 8) & 0xFFFF;
}


// --- UNIVERSAL SSL PINNING BYPASS (Most Aggressive) ---

function universalSSLBypass() {
    let bypassActive = false;
    
    // --- Hook SSLCopyPeerTrust ---
    // SSLCopyPeerTrust copies the trust object. We hook it to replace the trust
    // object with a successful result before the app can inspect it.
    let sslCopyPeerTrustPtr = null;
    const securityModule = Process.getModuleByName("Security") || Process.getModuleByName("Security.framework");

    if (securityModule) {
        sslCopyPeerTrustPtr = securityModule.findExportByName("SSLCopyPeerTrust");
    }

    if (sslCopyPeerTrustPtr) {
        console.log("[+] Found SSLCopyPeerTrust. Applying universal pinning bypass...");
        bypassActive = true;
        Interceptor.attach(sslCopyPeerTrustPtr, {
            onLeave: function(retval) {
                // SSLCopyPeerTrust returns a status code (0 for success). We force success.
                retval.replace(0); 
            }
        });
    } else {
        console.warn("[-] SSLCopyPeerTrust not found. Universal bypass partially disabled.");
    }

    // --- Hook SSLSetSessionOption ---
    // SSLSetSessionOption is used to set various options, including disabling cert verification.
    let sslSetSessionOptionPtr = null;
    if (securityModule) {
        sslSetSessionOptionPtr = securityModule.findExportByName("SSLSetSessionOption");
    }

    if (sslSetSessionOptionPtr) {
        console.log("[+] Found SSLSetSessionOption. Applying universal pinning bypass...");
        bypassActive = true;
        Interceptor.attach(sslSetSessionOptionPtr, {
            onEnter: function(args) {
                // The function signature is: OSStatus SSLSetSessionOption(SSLContextRef context, int option, Boolean value);
                const option = args[1].toInt32();
                
                if (option === K_SSL_SESSION_OPTION_DISABLE_CERT_VERIFICATION) {
                    // Force the value argument (args[2]) to TRUE (1)
                    args[2].replace(ptr(1));
                    console.log("[<<<] SSLSetSessionOption: Forced DISABLE_CERT_VERIFICATION to TRUE.");
                } else if (option === 9) { // Sometimes 9 is used for specific pinning flags
                    args[2].replace(ptr(0)); // Force to FALSE
                    console.log("[<<<] SSLSetSessionOption: Forced Pinning flag (9) to FALSE.");
                }
            }
        });
    } else {
        console.warn("[-] SSLSetSessionOption not found. Universal bypass partially disabled.");
    }
    
    // Hook SecTrustEvaluate as a robust fallback, using x1 for resultPtr
    let secTrustEvaluatePtr = null;
    if (securityModule) {
        secTrustEvaluatePtr = securityModule.findExportByName("SecTrustEvaluate");
    }

    if (secTrustEvaluatePtr) {
        console.log("[+] Found SecTrustEvaluate. Applying fallback bypass hook...");
        bypassActive = true;
        Interceptor.attach(secTrustEvaluatePtr, {
            onLeave: function(retval) {
                retval.replace(0); 
                const resultPtr = this.context.x1; 
                if (resultPtr && !resultPtr.isNull()) {
                    resultPtr.writeU32(K_SEC_TRUST_RESULT_PROCEED);
                    console.log("[<<<] SecTrustEvaluate bypassed (forced kSecTrustResultProceed).");
                }
            }
        });
    }

    if (!bypassActive) {
        console.error("[-] WARNING: No core SSL/Trust functions were successfully hooked. SSL pinning is likely still active.");
    }
    
    return bypassActive;
}


// --- Main Hooking Logic ---
try {
    // 1. **FIRST STEP: Execute Universal SSL Pinning Bypass**
    const bypassApplied = universalSSLBypass();
    
    // 2. Proceed with Traffic Redirection
    const libSystem = Process.getModuleByName("libSystem.B.dylib");

    let connectPtr = null;
    if (libSystem) {
        connectPtr = libSystem.findExportByName("connect");
    }

    if (connectPtr) {
        console.log(`[+] Found connect at ${connectPtr}`);

        const newIP_NBO = ipToNetworkByteOrder(PROXY_IP);
        const newPort_NBO = portToNetworkByteOrder(PROXY_PORT);

        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                try {
                    // The connect function signature is: int connect(int socket, const struct sockaddr *address, socklen_t address_len);
                    const addr = args[1];

                    if (addr.isNull()) {
                        return; // Safely exit if pointer is null
                    }
                    
                    const sa_family = addr.add(1).readU8(); // AF_INET is 2, AF_INET6 is 30

                    // Only intercept IPv4 connections (AF_INET = 2)
                    if (sa_family === 2) {
                        const originalPort = addr.add(2).readU16();
                        const originalIP = addr.add(4).readU32();

                        // Conversion for logging only
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

        console.log(`[+] Frida script loaded successfully. Traffic redirection is active. Universal SSL bypass status: ${bypassApplied ? 'Active' : 'Warning'}.`);

    } else {
        console.error("[-] Traffic redirection is DISABLED because 'connect' function could not be located in libSystem.B.dylib.");
        console.log(`[!] Script loaded. Universal SSL bypass status: ${bypassApplied ? 'Active' : 'Warning'}.`);
    }
} catch (e) {
    console.error(`[-] A critical error occurred during script initialization: ${e.message}`);
}
