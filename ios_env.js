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
        const NSBundle = ObjC.classes.NSBundle;
        const mainBundle = NSBundle.mainBundle();
        
        // Get the main application bundle path
        info.bundlePath = mainBundle.bundlePath().toString();

        // Get the home directory (sandbox root)
        const homeDir = ObjC.classes.NSHomeDirectory().toString();
        info.sandboxRoot = homeDir;

        // Use the successful homeDir to reliably construct standard sandboxed paths.
        if (homeDir) {
            info.libraryDir = homeDir + '/Library';
            info.cachesDir = homeDir + '/Library/Caches';
            info.documentsDir = homeDir + '/Documents'; // Direct construction via standard path
            info.tmpDir = homeDir + '/tmp';
            
            // Clean up old error field if successful
            delete info.directoryError;
        } else {
             info.directoryError = "NSHomeDirectory() returned null or empty string.";
        }

    } catch (e) {
        info.directoryError = "CRITICAL: Could not retrieve Objective-C directory paths: " + e.message;
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
        // --- UPDATED: Using Objective-C NSProcessInfo as a reliable fallback ---
        const NSProcessInfo = ObjC.classes.NSProcessInfo;
        const environment = NSProcessInfo.processInfo().environment();

        // Convert NSDictionary to a clean JavaScript object
        const envVars = {};
        const allKeys = environment.allKeys();
        for (let i = 0; i < allKeys.count(); i++) {
            const key = allKeys.objectAtIndex_(i).toString();
            const value = environment.objectForKey_(allKeys.objectAtIndex_(i)).toString();
            envVars[key] = value;
        }

        info.environmentVariables = envVars;
        
        if (Object.keys(envVars).length === 0) {
            info.envVarWarning = "Enumeration succeeded but returned zero environment variables. This might be normal for the simulator process.";
        } else {
            // Clean up old failure field if successful
            delete info.envVarFailure;
        }
        
    } catch (e) {
        // NSProcessInfo is highly likely to work on Simulator/macOS apps
        info.envVarFailure = "HARD FAILURE: Could not enumerate environment variables even with NSProcessInfo: " + e.message;
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
