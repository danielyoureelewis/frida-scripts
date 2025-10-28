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
// Constant for forced successful trust result
const K_SEC_TRUST_RESULT_PROCEED = 1; 

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
    // Port 8080 (0x1F90) will be represented as 0x901F in Little-Endian memory
    // but the connect call expects the actual network byte order in memory: 0x1F, 0x90
    // We write a U16 in Host-Endian and let Frida handle the system's memory layout.
    return (port >> 8) | (port << 8) & 0xFFFF;
}

/**
 * [SSL PINNING BYPASS]
 * Hooks SecTrustEvaluate and forces it to return success (kSecTrustResultProceed).
 * This uses the defensive search logic to account for different module loading states.
 */
function sslPinningBypass() {
    let secTrustEvaluatePtr = null;
    
    // Attempt to locate SecTrustEvaluate using common names and a fallback search
    const securityModule = Process.getModuleByName("Security") || Process.getModuleByName("Security.framework");

    if (securityModule) {
        secTrustEvaluatePtr = securityModule.findExportByName("SecTrustEvaluate");
    }

    if (!secTrustEvaluatePtr) {
        // Defensive fallback: Search for the export in ALL loaded modules
        try {
            secTrustEvaluatePtr = Module.findExportByName(null, "SecTrustEvaluate");
        } catch (e) {
            // Log warning if fallback fails
        }
    }

    if (secTrustEvaluatePtr) {
        console.log("[+] Found SecTrustEvaluate. Applying SSL Pinning bypass hook...");
        
        Interceptor.attach(secTrustEvaluatePtr, {
            onLeave: function(retval) {
                // SecTrustEvaluate returns OSStatus (0 for success). We force success.
                retval.replace(0); 
                
                // The result pointer (SecTrustResultType *) is typically the second argument (x1 on arm64).
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
        console.warn("[-] Could not find SecTrustEvaluate. SSL pinning bypass will not be active.");
        return false;
    }
}


// --- Main Hooking Logic ---
try {
    // 1. **FIRST STEP: Execute SSL Pinning Bypass**
    const bypassApplied = sslPinningBypass();
    
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
                    // We are interested in the second argument: const struct sockaddr *address (args[1])
                    const addr = args[1];

                    if (addr.isNull()) {
                        return; // Safely exit if pointer is null
                    }
                    
                    // 2. Read the address family (sa_family) from the sockaddr structure.
                    // It's located at offset 1 (1 byte after sa_len, which is usually 1 byte).
                    const sa_family = addr.add(1).readU8(); // AF_INET is 2, AF_INET6 is 30

                    // Only intercept IPv4 connections (AF_INET = 2)
                    if (sa_family === 2) {
                        // Structure is sockaddr_in (16 bytes)
                        // Offset 2: Port (2 bytes)
                        // Offset 4: IP Address (4 bytes)

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
                        
                        // Write new port (Network Byte Order)
                        addr.add(2).writeU16(newPort_NBO);

                        // Write new IP address (Network Byte Order)
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

        console.log(`[+] Frida script loaded successfully. Traffic redirection is active. SSL bypass status: ${bypassApplied ? 'Active' : 'Warning'}.`);

    } else {
        console.error("[-] Traffic redirection is DISABLED because 'connect' function could not be located in libSystem.B.dylib.");
        console.log(`[!] Script loaded. SSL bypass status: ${bypassApplied ? 'Active' : 'Warning'}.`);
    }
} catch (e) {
    console.error(`[-] A critical error occurred during script initialization: ${e.message}`);
}
