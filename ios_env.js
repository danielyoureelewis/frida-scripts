// This Frida script uses the Objective-C runtime (ObjC) to replicate the environment
// information gathering performed by tools like 'objection env' for an iOS application.
// It gathers key directories, environment variables, and loaded modules.

// Ensure ObjC runtime is available before trying to use it.
if (typeof ObjC === 'undefined') {
    throw new Error("ObjC runtime not available. This script must be run against an iOS or macOS target.");
}

/**
 * Gathers environment information including sandboxed directories,
 * environment variables, and loaded modules.
 * @returns {object} An object containing all gathered environment data.
 */
rpc.exports.getEnvironmentInfo = function () {
    const info = {};

    // 1. Get Application Directory Paths (iOS Sandboxed Paths)
    try {
        const NSFileManager = ObjC.classes.NSFileManager;
        const NSBundle = ObjC.classes.NSBundle;
        const fileManager = NSFileManager.defaultManager();

        // Get the main application bundle path
        const mainBundle = NSBundle.mainBundle();
        info.bundlePath = mainBundle.bundlePath().toString();

        // Get the home directory (sandbox root)
        const homeDir = ObjC.classes.NSHomeDirectory().toString();
        info.sandboxRoot = homeDir;

        // Construct standard sandboxed paths based on the home directory
        info.documentsDir = fileManager.URLsForDirectory_inDomains_(
            0x09, // NSDocumentDirectory
            0x01  // NSUserDomainMask
        ).objectAtIndex_(0).path().toString();
        
        info.libraryDir = homeDir + '/Library';
        info.cachesDir = homeDir + '/Library/Caches';

    } catch (e) {
        info.directoryError = "Could not retrieve Objective-C directory paths: " + e.message;
    }

    // 2. Get Process and System Information
    try {
        info.processId = Process.pid;
        info.processName = Process.getCurrentModule().name;
        info.platform = Process.platform;
        info.architecture = Process.arch;
    } catch (e) {
        info.processInfoError = "Could not retrieve basic process info: " + e.message;
    }

    // 3. Get Environment Variables
    try {
        info.environmentVariables = Process.enumerateEnvironmentVariables();
    } catch (e) {
        info.envVarError = "Could not enumerate environment variables: " + e.message;
    }


    // 4. Get Loaded Modules (Libraries/Frameworks)
    try {
        // We only return the name and base address to keep the output concise,
        // similar to what objection's 'env' output often summarizes.
        info.loadedModules = Process.enumerateModules().map(m => ({
            name: m.name,
            base: m.base.toString(),
            size: m.size
        }));
    } catch (e) {
        info.moduleError = "Could not enumerate loaded modules: " + e.message;
    }

    return info;
};
