/**
 * iOS Traffic Redirection and UNIVERSAL SSL Pinning Bypass Frida Script
 *
 * This version includes four layers of pinning bypass, with corrected Objective-C method hooking:
 * 1. Low-Level C/CoreTLS hooks (SSLCopyPeerTrust, SSLSetSessionOption).
 * 2. TrustKit specific hook.
 * 3. High-Level Objective-C Delegate hook (NSURLSession challenge handler).
 * 4. SecTrustEvaluate fallback.
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
// NSURLSession challenge disposition values
const NSURLSessionAuthChallengeUseCredential = 1;
// Default handling is 0, but we use 1 for success.
const NSURLSessionAuthChallengePerformDefaultHandling = 0; 
const NSURLAuthenticationMethodServerTrust = "NSURLAuthenticationMethodServerTrust";


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

// --- High-Level Delegate Bypass ---
// Hooks the NSURLSession delegate method responsible for handling server trust challenges.
function nsUrlSessionDelegateBypass() {
    let bypassApplied = false;

    if (ObjC.available) {
        try {
            // TARGETING THE TASK-LEVEL DELEGATE METHOD (most common and robust implementation)
            // Selector signature: URLSession:task:didReceiveChallenge:completionHandler:
            const selector = 'URLSession:task:didReceiveChallenge:completionHandler:';
            
            // ObjC.implement applies the hook across all classes that implement this selector.
            // The arguments are (self, _cmd, session, task, challenge, completionHandler)
            const imp = ObjC.implement(selector, function(session, task, challenge, completionHandler) {
                try {
                    const protectionSpace = challenge.protectionSpace();
                    const authMethod = protectionSpace.authenticationMethod().toString();

                    if (authMethod === NSURLAuthenticationMethodServerTrust) {
                        const serverTrust = protectionSpace.serverTrust();
                        
                        // We must check if serverTrust is not null before proceeding
                        if (!serverTrust.isNull()) {
                            const credential = ObjC.classes.NSURLCredential.credentialForTrust_(serverTrust);
                            
                            // Force USE_CREDENTIAL and pass the server's original trust credential.
                            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
                            
                            const hostName = protectionSpace.host() ? protectionSpace.host().toString() : 'Unknown Host';
                            console.log(`[<<<] NSURLSession Delegate Bypass: Handled server trust challenge for ${hostName}`);
                            return; // Exit the custom implementation
                        }
                    }
                } catch (e) {
                    console.error(`[!!!] Error inside delegate hook logic: ${e.message}`);
                }
                
                // FALLBACK: If the challenge is not server trust, or if logic above failed, 
                // call the completionHandler with default handling to avoid connection leaks.
                completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, null); 
            });
            
            // The ObjC.implement call itself applies the hook to the implementation pointer.
            // No need for Interceptor.attach here.
            
            console.log(`[+] NSURLSession Delegate hook applied to selector: ${selector}`);
            bypassApplied = true;

        } catch (e) {
            console.warn(`[-] NSURLSession Delegate hook failed: ${e.message}`);
        }
    }
    return bypassApplied;
}


// --- UNIVERSAL SSL PINNING BYPASS (Most Aggressive) ---

function universalSSLBypass() {
    let bypassActive = false;
    
    // --- 3. Objective-C Delegate Bypass ---
    if (nsUrlSessionDelegateBypass()) {
        bypassActive = true;
    }

    // Attempt to get the Security framework module first
    const securityModule = Process.getModuleByName("Security") || Process.getModuleByName("Security.framework");

    // --- TrustKit Pinning Bypass ---
    try {
        if (ObjC.available && ObjC.classes.TSKPinningValidator) {
            const evaluateTrust = ObjC.classes.TSKPinningValidator["- evaluateTrust:forHostname:"];
            
            Interceptor.attach(evaluateTrust.implementation, {
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        retval.replace(ptr(0));
                        console.log("[<<<] TrustKit Bypass: Forced TSKPinningValidator to return success (0).");
                    }
                }
            });
            console.log("[+] TrustKit PinningValidator hook applied.");
            bypassActive = true;
        }
    } catch (e) {
        console.warn(`[-] TrustKit hook failed (may not be present): ${e.message}`);
    }


    // --- Hook SSLCopyPeerTrust ---
    let sslCopyPeerTrustPtr = null;
    if (securityModule) {
        sslCopyPeerTrustPtr = securityModule.findExportByName("SSLCopyPeerTrust");
    }

    if (sslCopyPeerTrustPtr) {
        console.log("[+] Found SSLCopyPeerTrust. Applying universal pinning bypass...");
        bypassActive = true;
        Interceptor.attach(sslCopyPeerTrustPtr, {
            onLeave: function(retval) {
                retval.replace(0); 
            }
        });
    } else {
        console.warn("[-] SSLCopyPeerTrust not found. Universal bypass partially disabled.");
    }

    // --- Hook SSLSetSessionOption ---
    let sslSetSessionOptionPtr = null;
    if (securityModule) {
        sslSetSessionOptionPtr = securityModule.findExportByName("SSLSetSessionOption");
    }

    if (sslSetSessionOptionPtr) {
        console.log("[+] Found SSLSetSessionOption. Applying universal pinning bypass...");
        bypassActive = true;
        Interceptor.attach(sslSetSessionOptionPtr, {
            onEnter: function(args) {
                const option = args[1].toInt32();
                
                if (option === K_SSL_SESSION_OPTION_DISABLE_CERT_VERIFICATION) {
                    args[2].replace(ptr(1));
                    console.log("[<<<] SSLSetSessionOption: Forced DISABLE_CERT_VERIFICATION to TRUE.");
                } else if (option === 9) { 
                    args[2].replace(ptr(0)); 
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
