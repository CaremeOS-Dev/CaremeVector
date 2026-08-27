package org.matrix.vector.daemon.data

import java.nio.file.Path
import org.matrix.vector.ipc.LoadedModule
import org.matrix.vector.daemon.BuildConfig

data class ProcessScope(val processName: String, val uid: Int)

/**
 * An immutable snapshot of the Daemon's state. Any updates will generate a new copy of this class
 * and atomically swap the reference.
 */
data class DaemonState(
    // State non configurable for users
    //
    // CAREME: dex obfuscation stays off in every build, not only debug (upstream: !BuildConfig.DEBUG).
    // It rewrites the `Landroid/content/res/XRes` and `Lde/robv/android/xposed/` prefixes to random
    // names as each dex is loaded (daemon/src/main/jni/obfuscation.cpp). That is self-consistent
    // upstream, where XResources' super class is generated on the device and is renamed along with
    // it. On CaremeOS XResources extends android.content.res.Resources directly — ART 8.1 cannot
    // resolve a cross-dex super class at define-time, see XResources.java — so the renamed class and
    // the native-side name lookups no longer agree, and a release build died with SIGSEGV/SIGBUS in
    // system_server while loading modules. Obfuscation only frustrates module-side detection; a
    // booting framework is worth more here.
    val isDexObfuscateEnabled: Boolean = false,
    // States initialized after system services are ready
    val isCacheReady: Boolean = false,
    val managerUid: Int = -1,
    val miscPath: Path? = null,
    val modules: Map<String, LoadedModule> = emptyMap(),
    val scopes: Map<ProcessScope, List<LoadedModule>> = emptyMap(),
    /**
     * Modules the user enabled that the framework could not load, and why.
     *
     * The gap between the two notions of "module" this daemon holds — what was asked for, which
     * lives in the database, and what can actually be loaded, which lives here. They can disagree
     * legitimately: an APK whose path cannot be resolved, or whose DEX will not parse, stays
     * configured and never loads. That difference used to be discarded, and the module simply
     * appeared to be off; it is reported now, because it is the one thing a reader in that
     * situation needs to know.
     */
    val unloadable: Map<String, Int> = emptyMap(),
)
