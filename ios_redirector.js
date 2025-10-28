/**
 * iOS Traffic Redirection Frida Script
 *
 * This script hooks the low-level 'connect' function in libSystem.B.dylib
 * and redirects all TCP/IPv4 connection attempts to a specified proxy address.
 *
 * Proxy Target: 127.0.0.1:8080
 *
 * Usage: frida -U -f <BUNDLE_ID> -l traffic_redirector.js --no-pause
 */

// --- Configuration ---
const PROXY_IP = "127.0.0.1";
const PROXY_PORT = 8080;

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


// --- Main Hooking Logic ---
try {
    // 1. Find the address of the connect function in libSystem.B.dylib
    const connectPtr = Module.findExportByName("libSystem.B.dylib", "connect");

    if (connectPtr) {
        console.log(`[+] Found connect at ${connectPtr}`);

        const newIP_NBO = ipToNetworkByteOrder(PROXY_IP);
        const newPort_NBO = portToNetworkByteOrder(PROXY_PORT);

        Interceptor.attach(connectPtr, {
            onEnter: function (args) {
                // The connect function signature is: int connect(int socket, const struct sockaddr *address, socklen_t address_len);
                // We are interested in the second argument: const struct sockaddr *address (args[1])
                const addr = args[1];

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
                    
                    // Write new port (Network Byte Order)
                    addr.add(2).writeU16(newPort_NBO);

                    // Write new IP address (Network Byte Order)
                    addr.add(4).writeU32(newIP_NBO);

                    console.log(`[<<<] Redirected to ${PROXY_IP}:${PROXY_PORT}`);
                }
            },
            onLeave: function (retval) {
                // Connection result can be inspected here if needed
                // For now, we only care about modifying the destination on entry
            }
        });

        console.log(`[+] Frida script loaded successfully. All IPv4 traffic is being redirected to ${PROXY_IP}:${PROXY_PORT}.`);

    } else {
        console.error("[-] Could not find 'connect' export in libSystem.B.dylib.");
    }
} catch (e) {
    console.error(`[-] An error occurred: ${e.message}`);
}
