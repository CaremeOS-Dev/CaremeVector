package org.matrix.vector.impl.core

import android.app.ActivityThread
import android.os.Build
import android.os.IBinder
import dalvik.system.DexFile
import org.matrix.vector.util.Utils
import org.matrix.vector.ipc.IFrameworkService
import org.matrix.vector.impl.di.VectorBootstrap
import org.matrix.vector.impl.hookers.*
import org.matrix.vector.impl.hooks.VectorHookBuilder

/**
 * Modern framework initialization and bootstrap sequence. Deploys interceptors into the ART runtime
 * and handles early process deoptimization.
 */
object VectorStartup {

    // CAREME-DBG: temporary instrumentation
    @JvmStatic
    fun vdbg(msg: String) {
        try {
            java.io.FileWriter("/data/local/tmp/vdbg.txt", true).use {
                it.write("[vstartup ${android.os.Process.myPid()}] $msg\n")
            }
        } catch (t: Throwable) {
            // never let logging break injection
        }
    }

    @JvmStatic
    fun init(
        isSystem: Boolean,
        processName: String?,
        appDir: String?,
        service: IFrameworkService?,
    ) {
        vdbg("VectorStartup.init: VectorServiceClient.init")
        VectorServiceClient.init(service, processName ?: "android")
        vdbg("VectorStartup.init: deoptBootMethods")
        VectorDeopter.deoptBootMethods()
        vdbg("VectorStartup.init: done")
    }

    /**
     * Registers a pre-built [LoadedApk] whose constructor ran before the hooks were installed -- the
     * LSPatch rootless target being the one case. Once tracked, [LoadedApkCreateAppFactoryHooker] and
     * [LoadedApkCreateCLHooker] dispatch its `onPackageLoaded`/`onPackageReady` (and legacy
     * `handleLoadPackage`) exactly once when its class loader is realized, with `onPackageLoaded`
     * running *before* the app's `AppComponentFactory` static initializer.
     */
    @JvmStatic
    fun trackLoadedApk(loadedApk: Any) {
        LoadedApkTracker.activeApks.add(loadedApk)
    }

    @JvmStatic
    fun bootstrap(isSystem: Boolean, systemServerStarted: Boolean) {
        vdbg("bootstrap: dispatchUncaughtException hook")
        // Crash Dump Interceptor
        Thread::class
            .java
            .declaredMethods
            .firstOrNull { it.name == "dispatchUncaughtException" }
            ?.let { VectorHookBuilder(it).intercept(CrashDumpHooker) }

        // Process-specific Interceptors
        if (isSystem) {
            vdbg("bootstrap: handleSystemServerProcess hook")
            val zygoteInitClass = Class.forName("com.android.internal.os.ZygoteInit")
            zygoteInitClass.declaredMethods
                .filter { it.name == "handleSystemServerProcess" }
                .forEach { VectorHookBuilder(it).intercept(HandleSystemServerProcessHooker) }
        } else {
            DexFile::class
                .java
                .declaredMethods
                .filter {
                    it.name == "openDexFile" ||
                        it.name == "openInMemoryDexFile" ||
                        it.name == "openInMemoryDexFiles"
                }
                .forEach { VectorHookBuilder(it).intercept(DexTrustHooker) }
        }

        // Application Load Interceptors
        vdbg("bootstrap: LoadedApk ctor hooks")
        val loadedApkClass = Class.forName("android.app.LoadedApk")
        loadedApkClass.declaredConstructors.forEach {
            // Hook all constructors of LoadedApk to catch early instantiations securely
            VectorHookBuilder(it).intercept(LoadedApkCtorHooker)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            loadedApkClass.declaredMethods
                .filter { it.name == "createAppFactory" }
                .forEach { VectorHookBuilder(it).intercept(LoadedApkCreateAppFactoryHooker) }
        }

        loadedApkClass.declaredMethods
            .filter { it.name == "createOrUpdateClassLoaderLocked" }
            .forEach { VectorHookBuilder(it).intercept(LoadedApkCreateCLHooker) }

        // ActivityThread Attachment Interceptor
        vdbg("bootstrap: ActivityThread.attach hook")
        val activityThreadClass = Class.forName("android.app.ActivityThread")
        activityThreadClass.declaredMethods
            .filter { it.name == "attach" }
            .forEach { VectorHookBuilder(it).intercept(AppAttachHooker) }

        // Late System Server Injection
        if (systemServerStarted) {
            val activityService: IBinder? = android.os.ServiceManager.getService("activity")
            if (activityService != null) {
                val classLoader = activityService.javaClass.classLoader
                if (classLoader != null) {
                    // Manually trigger the routines that the hooks normally would
                    HandleSystemServerProcessHooker.initSystemServer(classLoader, isLate = true)

                    // ActivityThread.attach ran before we were injected, so AppAttachHooker will
                    // never fire here and nothing else instantiates modules. Without this,
                    // dispatchSystemServerLoaded below would notify an empty module set.
                    val activityThread = ActivityThread.currentActivityThread()
                    if (activityThread != null) {
                        VectorBootstrap.withLegacy { it.loadModules(activityThread) }
                    } else {
                        Utils.logW(
                            "Late system server injection: no current ActivityThread, modules cannot be loaded"
                        )
                    }

                    // Say plainly what this is. onSystemServerStarting is documented as "system
                    // server is ready to start critical services", which is no longer true here -
                    // the services are already running. Modules that key off it should treat a
                    // late dispatch as best effort.
                    Utils.logW(
                        "Late system server injection: dispatching onSystemServerStarting after " +
                            "system server has already started; critical services are live"
                    )
                    StartBootstrapServicesHooker.dispatchSystemServerLoaded(classLoader)
                }
            }
        }
        vdbg("bootstrap: done")
    }
}
