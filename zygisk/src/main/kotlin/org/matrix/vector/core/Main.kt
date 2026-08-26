package org.matrix.vector.core

import android.os.IBinder
import android.os.Process
import java.io.FileWriter
import org.matrix.vector.ipc.IFrameworkService
import org.matrix.vector.util.Log
import org.matrix.vector.util.Utils
import org.matrix.vector.BuildConfig
import org.matrix.vector.GrapheneDclHooker
import org.matrix.vector.ParasiticManagerHooker
import org.matrix.vector.ParasiticManagerSystemHooker
import org.matrix.vector.Startup
import org.matrix.vector.impl.core.VectorServiceClient

/** Main entry point for the Java-side loader, invoked via JNI from the Vector Zygisk module. */
object Main {

    // CAREME-DBG: temporary instrumentation to locate the system_server death inside forkCommon.
    @JvmStatic
    fun vdbg(msg: String) {
        try {
            FileWriter("/data/local/tmp/vdbg.txt", true).use {
                it.write("[java ${Process.myPid()}] $msg\n")
            }
        } catch (t: Throwable) {
            // never let logging break injection
        }
    }

    @Suppress("DEPRECATION")
    private class ExitTracer : SecurityManager() {
        override fun checkExit(status: Int) {
            val sb = StringBuilder("checkExit(").append(status).append(") intercepted, stack:\n")
            for (el in Throwable().stackTrace) sb.append("  at ").append(el).append('\n')
            vdbg(sb.toString())
            // do not block: keep behavior identical to no-security-manager
        }
        override fun checkPermission(perm: java.security.Permission?) {}
        override fun checkPermission(perm: java.security.Permission?, context: Any?) {}
        override fun checkAccess(t: Thread?) {}
        override fun checkAccess(g: ThreadGroup?) {}
        override fun checkExec(cmd: String?) {}
        override fun checkLink(lib: String?) {}
        override fun checkRead(fd: java.io.FileDescriptor?) {}
        override fun checkRead(file: String?) {}
        override fun checkRead(file: String?, context: Any?) {}
        override fun checkWrite(fd: java.io.FileDescriptor?) {}
        override fun checkWrite(file: String?) {}
        override fun checkDelete(file: String?) {}
        override fun checkConnect(host: String?, port: Int) {}
        override fun checkConnect(host: String?, port: Int, context: Any?) {}
        override fun checkListen(port: Int) {}
        override fun checkAccept(host: String?, port: Int) {}
        override fun checkMulticast(maddr: java.net.InetAddress?) {}
        override fun checkMulticast(maddr: java.net.InetAddress?, ttl: Byte) {}
        override fun checkPropertiesAccess() {}
        override fun checkPropertyAccess(key: String?) {}
        override fun checkTopLevelWindow(window: Any?): Boolean = true
        override fun checkPrintJobAccess() {}
        override fun checkSystemClipboardAccess() {}
        override fun checkAwtEventQueueAccess() {}
        override fun checkPackageAccess(pkg: String?) {}
        override fun checkPackageDefinition(pkg: String?) {}
        override fun checkSetFactory() {}
        override fun checkSecurityAccess(target: String?) {}
        override fun checkMemberAccess(clazz: Class<*>, which: Int) {}
    }

    private fun installExitTracer() {
        runCatching { System.setSecurityManager(ExitTracer()) }
            .onFailure { vdbg("installExitTracer failed: $it") }
            .onSuccess { vdbg("exit tracer installed") }
    }

    /**
     * Shared initialization logic for both System Server and Application processes.
     *
     * @param isSystem True if this is the system_server process.
     * @param isLateInject True if Zygisk APIs are not invoked via hooks
     * @param niceName The process name (e.g., package name or "system").
     * @param appDir The application's data directory.
     * @param binder The Binder token associated with the application service.
     */
    @JvmStatic
    fun forkCommon(
        isSystem: Boolean,
        isLateInject: Boolean,
        niceName: String,
        appDir: String?,
        binder: IBinder,
    ) {
        vdbg("forkCommon enter: isSystem=$isSystem late=$isLateInject name=$niceName dir=$appDir binder=$binder")
        installExitTracer()

        // Initialize system-specific resolution hooks if in system_server
        if (isSystem) {
            vdbg("step: ParasiticManagerSystemHooker.start")
            ParasiticManagerSystemHooker.start()
            vdbg("step: GrapheneDclHooker.start")
            GrapheneDclHooker.start()
        }

        // Initialize Xposed bridge components
        vdbg("step: asInterface")
        val appService = IFrameworkService.Stub.asInterface(binder)
        vdbg("step: Startup.initXposed")
        Startup.initXposed(isSystem, niceName, appDir, appService)
        vdbg("step: initXposed returned")

        // Configure logging levels from the service client
        runCatching { Log.muted = VectorServiceClient.isLogMuted }
            .onFailure { t -> Utils.logE("Failed to configure logs from service", t) }

        // Check if this process is the designated Vector Manager.
        if (niceName == BuildConfig.ManagerPackageName) {
            ParasiticManagerHooker.isParasitic = Process.myUid() == BuildConfig.HostPackageUid
            val type = if (ParasiticManagerHooker.isParasitic) "parasitic" else "user-installed"
            if (ParasiticManagerHooker.start()) {
                Utils.logI("Manager ($type) loaded into host, skipping standard bootstrap.")
                vdbg("forkCommon done (manager path)")
                return
            }
        }

        // Standard Xposed module loading for third-party apps
        Utils.logV("Loading Vector/Xposed for $niceName (UID: ${Process.myUid()})")
        vdbg("step: Startup.bootstrapXposed")
        Startup.bootstrapXposed(isSystem && isLateInject)
        vdbg("forkCommon done (bootstrap path)")
    }
}
