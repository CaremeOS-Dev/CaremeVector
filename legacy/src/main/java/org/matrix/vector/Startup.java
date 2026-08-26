package org.matrix.vector;

import org.matrix.vector.ipc.IFrameworkService;
import org.matrix.vector.util.Utils;
import org.matrix.vector.impl.core.VectorStartup;
import org.matrix.vector.impl.di.VectorBootstrap;
import org.matrix.vector.legacy.LegacyDelegateImpl;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedInit;

public class Startup {

    // CAREME-DBG: temporary instrumentation
    public static void vdbg(String msg) {
        try {
            java.io.FileWriter w = new java.io.FileWriter("/data/local/tmp/vdbg.txt", true);
            w.write("[startup " + android.os.Process.myPid() + "] " + msg + "\n");
            w.close();
        } catch (Throwable t) {
            // never let logging break injection
        }
    }

    public static void bootstrapXposed(boolean systemServerStarted) {
        try {
            vdbg("bootstrapXposed: VectorStartup.bootstrap");
            VectorStartup.bootstrap(XposedInit.startsSystemServer, systemServerStarted);
            vdbg("bootstrapXposed: XposedInit.loadLegacyModules");
            XposedInit.loadLegacyModules();
            vdbg("bootstrapXposed: done");
        } catch (Throwable t) {
            Utils.logE("Error during framework initialization", t);
            vdbg("bootstrapXposed threw: " + t);
        }
    }

    /**
     * Registers a pre-built {@code LoadedApk} (the LSPatch rootless target) with the modern hooks so
     * its package lifecycle is dispatched when its class loader is realized. See
     * {@link VectorStartup#trackLoadedApk(Object)}.
     */
    public static void trackLoadedApk(Object loadedApk) {
        VectorStartup.trackLoadedApk(loadedApk);
    }

    public static void initXposed(boolean isSystem, String processName, String appDir, IFrameworkService service) {
        // Establish the Dependency Injection contract
        vdbg("initXposed: VectorBootstrap.init");
        VectorBootstrap.INSTANCE.init(new LegacyDelegateImpl());

        // Initialize legacy resources and state
        // CAREME: initXResources is deferred to XposedInit.hookResources() first use.
        // Calling Resources.getSystem() this early (inside the forked system_server, before
        // overlay idmaps exist) makes CaremeOS's libandroid_runtime exec /system/bin/idmap
        // IN PLACE, wiping the system_server image; the zygote then suicides and loops.
        vdbg("initXposed: XposedBridge.initXResources DEFERRED");
        XposedInit.startsSystemServer = isSystem;

        // Hand off execution to the modern framework initialization
        vdbg("initXposed: VectorStartup.init");
        VectorStartup.init(isSystem, processName, appDir, service);
        vdbg("initXposed: done");
    }
}
