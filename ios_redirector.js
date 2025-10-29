/**
 * iOS DNS Redirection Frida Script
 *
 * This script hooks the low-level DNS resolution function 'getaddrinfo' and 
 * forces all domain names to resolve to the proxy IP (127.0.0.1) on the proxy port (8080).
 *
 * This approach preserves the original destination hostname context (SNI/Host headers), 
 * which often fixes SSL handshake failures (-1200) caused by losing context in connect() hooks.
 *
 * Proxy Target: 127.0.0.1:8080
 *
 * Usage: frida -U -f <BUNDLE_ID> -l dns_redirector.js --no-pause
 *
 * If you need to bypass SSL pinning/trust, load ssl_bypass.js alongside this file.
 */

// --- Configuration ---
const PROXY_IP = "127.0.0.1";
const PROXY_PORT = 8080;

// Set AF_INET explicitly for clarity
const AF_INET = 2;
// sockaddr_in is 16 bytes long
const SOCKADDR_IN_LEN = 16; 

// --- Utility Functions for Byte Order and IP Conversion ---

// Convert port (host byte order) to network byte order (Big-Endian)
function portToNetworkByteOrder(port) {
    return (port >> 8) | (port << 8) & 0xFFFF;
}

// Convert IP string (e.g., "127.0.0.1") to its network byte order 32-bit integer
function ipToNetworkByteOrder(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) {
        throw new Error("Invalid IPv4 address format.");
    }
    return (parseInt(parts[0], 10) << 24 |
            parseInt(parts[1], 10) << 16 |
            parseInt(parts[2], 10) << 8 |
            parseInt(parts[3], 10)) >>> 0;
}

// --- DNS Redirection Hook (getaddrinfo) ---
try {
    // getaddrinfo is the function used by the system to resolve hostnames to IP addresses.
    const getaddrinfoPtr = Module.findExportByName("libSystem.B.dylib", "getaddrinfo");

    if (getaddrinfoPtr) {
        console.log(`[+] Found getaddrinfo at ${getaddrinfoPtr}`);

        const newPort_NBO = portToNetworkByteOrder(PROXY_PORT);
        const newIP_NBO = ipToNetworkByteOrder(PROXY_IP);

        Interceptor.attach(getaddrinfoPtr, {
            onEnter: function (args) {
                // int getaddrinfo(const char *hostname, const char *servname, const struct addrinfo *hints, struct addrinfo **res);
                const hostnamePtr = args[0];
                const servnamePtr = args[1];

                if (hostnamePtr.isNull()) {
                    // Do not intercept if hostname is NULL (e.g., reverse lookups)
                    return;
                }

                // Read the original hostname
                const hostname = hostnamePtr.readUtf8String();
                const servname = servnamePtr.isNull() ? 'null' : servnamePtr.readUtf8String();

                // Store context for onLeave
                this.resPtrPtr = args[3];

                if (hostname && !hostname.startsWith(PROXY_IP)) {
                    // We will redirect all lookups except for our proxy IP itself to avoid loops.
                    
                    console.log(`[***] Intercepting DNS lookup for ${hostname} on port ${servname}...`);
                    this.doRedirect = true;
                }
            },
            onLeave: function (retval) {
                // Only modify the result if getaddrinfo succeeded (retval is 0) and we intended to redirect
                if (retval.toS32() === 0 && this.doRedirect) {
                    
                    // The result (res) is a pointer to a struct addrinfo chain.
                    // We will replace the first node in the chain to point to our proxy.
                    const resPtr = this.resPtrPtr.readPointer();
                    
                    if (!resPtr.isNull()) {
                        // Check the address family ai_family (usually at offset 8 on 64-bit Darwin)
                        const ai_family = resPtr.add(8).readS32();

                        if (ai_family === AF_INET) {
                            // On 64-bit Darwin/iOS, the pointer to sockaddr struct (ai_addr) is reliably at offset 32.
                            // FIX: Changed offset from 24 to 32 for 64-bit ABI compatibility.
                            const ai_addr_ptr = resPtr.add(32).readPointer();
                            
                            if (!ai_addr_ptr.isNull()) {
                                // sockaddr_in structure: 16 bytes total
                                // Offset 0: length (1 byte)
                                // Offset 1: family (1 byte - AF_INET=2)
                                // Offset 2: port (2 bytes - NBO)
                                // Offset 4: IP (4 bytes - NBO)
                                
                                // Set length (sa_len)
                                ai_addr_ptr.writeU8(SOCKADDR_IN_LEN); 
                                // Set family to AF_INET (2)
                                ai_addr_ptr.add(1).writeU8(AF_INET);
                                // Set port to proxy port (NBO)
                                ai_addr_ptr.add(2).writeU16(newPort_NBO);
                                // Set IP to proxy IP (NBO)
                                ai_addr_ptr.add(4).writeU32(newIP_NBO);

                                console.log(`[<<<] DNS resolution result modified to proxy: ${PROXY_IP}:${PROXY_PORT}`);
                            } else {
                                console.warn("[-] Failed to find ai_addr pointer to overwrite.");
                            }
                        } else {
                            // If it's IPv6, we would need to map to ::ffff:127.0.0.1.
                            console.warn("[-] Resolved address is not IPv4. Skipping modification.");
                        }
                    }
                }
            }
        });

        console.log(`[+] DNS hook loaded. Hostnames will resolve to ${PROXY_IP}:${PROXY_PORT}.`);

    } else {
        console.error("[-] Could not find 'getaddrinfo' export in libSystem.B.dylib. Redirection may fail.");
    }
} catch (e) {
    console.error(`[-] An error occurred during getaddrinfo hooking: ${e.message}`);
}
