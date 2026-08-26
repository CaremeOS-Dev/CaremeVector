#include <common/config.h>
#include <common/logging.h>
#include <core/context.h>
#include <core/native_api.h>
#include <elf/elf_image.h>
#include <elf/symbol_cache.h>
#include <jni/jni_bridge.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <zygisk.hpp>

#include "ipc_bridge.h"

// CAREME-DBG: temporary instrumentation to catch whoever terminates system_server.
#include <dlfcn.h>
#include <dobby.h>
#include <fcntl.h>
#include <link.h>
#include <unwind.h>

namespace caremedbg {

static void vlog(const char *msg) {
    int fd = open("/data/local/tmp/vdbg.txt", O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd >= 0) {
        // Tag every line with the pid so parent (system_server) vs. a fork() child
        // (e.g. verifySystemIdmaps' idmap child) is unambiguous in the log.
        char pfx[24];
        int n = snprintf(pfx, sizeof pfx, "[pid %d] ", getpid());
        if (n > 0) write(fd, pfx, n);
        write(fd, msg, strlen(msg));
        write(fd, "\n", 1);
        close(fd);
    }
}

static _Unwind_Reason_Code bt_cb(struct _Unwind_Context *ctx, void *) {
    void *ip = reinterpret_cast<void *>(_Unwind_GetIP(ctx));
    if (ip) {
        char buf[96];
        snprintf(buf, sizeof buf, "[vdbg-native]   pc %p", ip);
        vlog(buf);
    }
    return _URC_NO_REASON;
}

static void (*orig_exit)(int) = nullptr;
static void (*orig__exit)(int) = nullptr;
static void (*orig_abort)(void) = nullptr;

static void my_exit(int status) {
    char buf[96];
    snprintf(buf, sizeof buf, "[vdbg-native] exit(%d) called! backtrace:", status);
    vlog(buf);
    _Unwind_Backtrace(bt_cb, nullptr);
    orig_exit(status);
}

static void my__exit(int status) {
    char buf[96];
    snprintf(buf, sizeof buf, "[vdbg-native] _exit(%d) called! backtrace:", status);
    vlog(buf);
    _Unwind_Backtrace(bt_cb, nullptr);
    orig__exit(status);
}

static void my_abort(void) {
    vlog("[vdbg-native] abort() called! backtrace:");
    _Unwind_Backtrace(bt_cb, nullptr);
    orig_abort();
}

// CAREME idmap fix. android::verifySystemIdmaps(const char*) is CaremeOS's eager overlay-idmap
// pre-scan, reached from android_content_AssetManager_init(isSystem=true) i.e. the first
// Resources.getSystem() in a process. Confirmed via IDA + ftrace: in the ptrace-injected
// system_server its fork() effectively returns 0 in the parent, so system_server's own main
// thread runs the child branch and execv("/system/bin/idmap") IN-PLACE, replacing the whole
// process (SIGCHLD to zygote -> zygote self-terminates -> restart loop). A resource-hooking
// module in the `system` scope makes Vector call getSystem() during module load, which is what
// trips it. Neutralising the pre-scan is a functional no-op on this device: nothing in
// /vendor/overlay targets "android", and libandroidfw creates any overlay idmap it actually
// needs lazily and in-process (AssetManager::createIdmap, no exec), so resource overlays and
// full XResources hooking keep working.
static void (*orig_verifySystemIdmaps)(const char *) = nullptr;
static void my_verifySystemIdmaps(const char *) {
    vlog("[vdbg-native] verifySystemIdmaps() neutralized (skipped in-place idmap exec)");
}

// libandroid_runtime.so is stripped to a .gnu_debugdata MiniDebugInfo whose in-process XZ decode
// is unreliable here, so resolve the local symbol by its known ELF vaddr against the runtime load
// bias from dl_iterate_phdr instead. verifySystemIdmaps is at vaddr 0xbb3b1 (Thumb bit set);
// prologue `PUSH {R4-R6,LR}; SUB SP,SP,#0x120` == 70 b5 c8 b0 is checked before hooking so a
// firmware whose layout differs is left untouched rather than mis-patched.
static uintptr_t g_art_runtime_bias = 0;
static int art_runtime_phdr_cb(struct dl_phdr_info *info, size_t, void *) {
    if (info->dlpi_name && strstr(info->dlpi_name, "libandroid_runtime.so")) {
        g_art_runtime_bias = static_cast<uintptr_t>(info->dlpi_addr);
        return 1;  // found; stop iterating
    }
    return 0;
}

static void install_idmap_neutralizer() {
    static bool done = false;
    if (done) return;
    done = true;
    g_art_runtime_bias = 0;
    dl_iterate_phdr(art_runtime_phdr_cb, nullptr);
    if (!g_art_runtime_bias) {
        vlog("[vdbg-native] idmap-neutralizer: libandroid_runtime.so not mapped");
        return;
    }
    constexpr uintptr_t kVerifyVaddr = 0xbb3b1;  // Thumb bit set
    uintptr_t thumb_addr = g_art_runtime_bias + kVerifyVaddr;
    const auto *code = reinterpret_cast<const unsigned char *>(thumb_addr & ~static_cast<uintptr_t>(1));
    static const unsigned char kSig[4] = {0x70, 0xb5, 0xc8, 0xb0};
    if (memcmp(code, kSig, sizeof kSig) != 0) {
        char buf[128];
        snprintf(buf, sizeof buf,
                 "[vdbg-native] idmap-neutralizer: sig mismatch @ %p (%02x %02x %02x %02x), skip",
                 code, code[0], code[1], code[2], code[3]);
        vlog(buf);
        return;
    }
    int rc = DobbyHook(reinterpret_cast<void *>(thumb_addr),
                       reinterpret_cast<void *>(&my_verifySystemIdmaps),
                       reinterpret_cast<void **>(&orig_verifySystemIdmaps));
    char buf[96];
    snprintf(buf, sizeof buf, "[vdbg-native] verifySystemIdmaps hooked @ %p rc=%d", (void *)thumb_addr,
             rc);
    vlog(buf);
}

static void install_exit_hooks() {
    static bool done = false;
    if (done) return;
    done = true;
    void *libc = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) {
        vlog("[vdbg-native] install_exit_hooks: no libc handle");
        return;
    }
    int ok = 0;
    if (void *p = dlsym(libc, "exit"))
        ok += DobbyHook(p, reinterpret_cast<void *>(&my_exit),
                        reinterpret_cast<void **>(&orig_exit)) == 0;
    if (void *p = dlsym(libc, "_exit"))
        ok += DobbyHook(p, reinterpret_cast<void *>(&my__exit),
                        reinterpret_cast<void **>(&orig__exit)) == 0;
    if (void *p = dlsym(libc, "abort"))
        ok += DobbyHook(p, reinterpret_cast<void *>(&my_abort),
                        reinterpret_cast<void **>(&orig_abort)) == 0;
    // NOTE: no execve hook. CaremeOS's verifySystemIdmaps() does a normal fork()+child execv()
    // of /system/bin/idmap (confirmed via IDA: fork@LIBC, not an in-place exec). The idmap child
    // is malloc-free before execv (ro.boot.vendor.overlay.theme is empty) and idmap finds no
    // android-targeted static overlay, so it exits 0 and system_server survives — exactly as the
    // uninjected boot does. The previous always-on execve blocker turned that clean child execv
    // into exit(1) -> fork-unsafe static dtor -> bad free -> SIGABRT, which is what killed the
    // framework. exit/_exit/abort stay hooked purely as (pid-tagged) diagnostics for this round.
    char buf[64];
    snprintf(buf, sizeof buf, "[vdbg-native] exit hooks installed: %d (no execve blocker)", ok);
    vlog(buf);
    install_idmap_neutralizer();
}

}  // namespace caremedbg

namespace vector::native::module {

// --- Process UID Constants ---
// Values used to identify special Android processes to avoid injection.
// https://android.googlesource.com/platform/system/core/+/master/libcutils/include/private/android_filesystem_config.h

// The range of UIDs used for isolated processes (e.g., web renderers, WebView).
constexpr int FIRST_ISOLATED_UID = 99000;
constexpr int LAST_ISOLATED_UID = 99999;

// The range of UIDs used for application zygotes, which are also not targets.
constexpr int FIRST_APP_ZYGOTE_ISOLATED_UID = 90000;
constexpr int LAST_APP_ZYGOTE_ISOLATED_UID = 98999;

// UID for the process responsible for creating shared RELRO files.
constexpr int SHARED_RELRO_UID = 1037;

// Android uses this to separate users. UID = AppID + UserID * 10000.
constexpr int PER_USER_RANGE = 100000;

// Defined via CMake generated marcos
constexpr uid_t kHostPackageUid = INJECTED_PACKAGE_UID;
const char *const kHostPackageName = VECTOR_STR(INJECTED_PACKAGE_NAME);
const char *const kManagerPackageName = VECTOR_STR(MANAGER_PACKAGE_NAME);
constexpr uid_t GID_INET = 3003;  // Android's Internet group ID.

enum RuntimeFlags : uint32_t {
    // Flags defined by NeoZygisk
    LATE_INJECT = 1 << 30,
};

// A simply ConfigBridge implemnetation holding obfuscation maps in memory
using obfuscation_map_t = std::map<std::string, std::string>;
class ConfigImpl : public ConfigBridge {
public:
    inline static void Init() { instance_ = std::make_unique<ConfigImpl>(); }

    virtual obfuscation_map_t &obfuscation_map() override { return obfuscation_map_; }

    virtual void obfuscation_map(obfuscation_map_t m) override { obfuscation_map_ = std::move(m); }

private:
    ConfigImpl() = default;

    friend std::unique_ptr<ConfigImpl> std::make_unique<ConfigImpl>();
    obfuscation_map_t obfuscation_map_;
};

/**
 * @class VectorModule
 * @brief The core implementation of the Zygisk module for the Vector framework.
 *
 * This class is the main entry point for Zygisk. It inherits from:
 * - zygisk::ModuleBase:      To receive lifecycle callbacks from the Zygisk loader.
 * - vector::native::Context: To gain the core injection capabilities (DEX loading, ART hooking)
 *                            from the 'native' library.
 *
 * It orchestrates the injection process by deciding which processes to target,
 * using the IPCBridge to fetch the framework from the manager service, and then
 * using the Context base to perform the actual injection.
 */
class VectorModule : public zygisk::ModuleBase, public vector::native::Context {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override;
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override;
    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override;
    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override;
    void postServerSpecialize(const zygisk::ServerSpecializeArgs *args) override;

protected:
    /**
     * @brief Provides the concrete implementation for loading the framework DEX.
     *
     * This method is a pure virtual in the native::core::Context base class and
     * must be implemented here.
     * It uses an InMemoryDexClassLoader to load our framework into the target process.
     */
    void LoadDex(JNIEnv *env, PreloadedDex &&dex) override;

    /**
     * @brief Provides the concrete implementation for finding the Java entry
     * class.
     *
     * This method is also a pure virtual in the base class.
     * It uses the obfuscation map to determine the real entry class name and
     * finds it in the ClassLoader we created in LoadDex.
     */
    void SetupEntryClass(JNIEnv *env) override;

private:
    /**
     * @brief Encapsulates the logic for telling Zygisk whether to unload our library.
     *
     * If we don't inject into a process, we allow Zygisk to dlclose our .so.
     * Otherwise, we MUST prevent this.
     * @param unload True to allow unloading, false to prevent it.
     */
    void SetAllowUnload(bool unload);

    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;

    // --- ART Hooker Configuration ---
    const lsplant::InitInfo init_info_{
        .inline_hooker =
            [](auto target, auto replace) {
                void *backup = nullptr;
                return HookInline(target, replace, &backup) == 0 ? backup : nullptr;
            },
        .inline_unhooker = [](auto target) { return UnhookInline(target) == 0; },
        .art_symbol_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbAddress(symbol); },
        .art_symbol_prefix_resolver =
            [](auto symbol) { return ElfSymbolCache::GetArt()->getSymbPrefixFirstAddress(symbol); },
        .generated_class_name = "Vector_",
        .generated_source_name = "Dobby",
    };

    // State managed within the class instance for each forked process.
    bool should_inject_ = false;
    bool is_manager_app_ = false;
};

// =========================================================================================
// Implementation of VectorModule
// =========================================================================================

void VectorModule::LoadDex(JNIEnv *env, PreloadedDex &&dex) {
    LOGV("Loading framework DEX into memory (size: {}).", dex.size());

    // Get the system ClassLoader. This will be the parent of our new loader.
    auto classloader_class = lsplant::JNI_FindClass(env, "java/lang/ClassLoader");
    if (!classloader_class) {
        LOGE("Failed to find java.lang.ClassLoader");
        return;
    }
    auto getsyscl_mid = lsplant::JNI_GetStaticMethodID(
        env, classloader_class.get(), "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    auto system_classloader =
        lsplant::JNI_CallStaticObjectMethod(env, classloader_class.get(), getsyscl_mid);
    if (!system_classloader) {
        LOGE("Failed to get SystemClassLoader");
        return;
    }

    // Create a Java ByteBuffer wrapping our in-memory DEX data.
    auto byte_buffer_class = lsplant::JNI_FindClass(env, "java/nio/ByteBuffer");
    if (!byte_buffer_class) {
        LOGE("Failed to find java.nio.ByteBuffer");
        return;
    }
    auto dex_buffer =
        lsplant::ScopedLocalRef(env, env->NewDirectByteBuffer(dex.data(), dex.size()));
    if (!dex_buffer) {
        LOGE("Failed to create DirectByteBuffer for DEX.");
        return;
    }

    // Create an InMemoryDexClassLoader instance.
    auto in_memory_cl_class = lsplant::JNI_FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    if (!in_memory_cl_class) {
        LOGE("Failed to find InMemoryDexClassLoader.");
        return;
    }
    auto init_mid = lsplant::JNI_GetMethodID(env, in_memory_cl_class.get(), "<init>",
                                             "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!init_mid) {
        LOGE("Failed to find InMemoryDexClassLoader constructor.");
        return;
    }

    auto new_cl =
        lsplant::ScopedLocalRef(env, env->NewObject(in_memory_cl_class.get(), init_mid,
                                                    dex_buffer.get(), system_classloader.get()));
    if (env->ExceptionCheck() || !new_cl) {
        LOGE("Failed to create InMemoryDexClassLoader instance.");
        env->ExceptionClear();
        return;
    }

    // Store a global reference to our new ClassLoader.
    inject_class_loader_ = env->NewGlobalRef(new_cl.get());
    LOGV("Framework ClassLoader created successfully.");
}

void VectorModule::SetupEntryClass(JNIEnv *env) {
    if (!inject_class_loader_) {
        LOGE("Cannot setup entry class: ClassLoader is null.");
        return;
    }

    // Use the obfuscation map from the config to get the real class name.
    const auto &obfs_map = ConfigBridge::GetInstance()->obfuscation_map();
    std::string entry_class_name;
    entry_class_name = obfs_map.at("org.matrix.vector.core.") + "Main";

    // We must find the class through our custom ClassLoader.
    auto entry_class = this->FindClassFromLoader(env, inject_class_loader_, entry_class_name);
    if (!entry_class) {
        LOGE("Failed to find entry class '{}' in the loaded DEX.", entry_class_name.c_str());
        return;
    }

    // Store a global reference to the entry class.
    entry_class_ = lsplant::JNI_NewGlobalRef(env, entry_class);
    LOGV("Framework entry class '{}' located.", entry_class_name.c_str());
}

void VectorModule::onLoad(zygisk::Api *api, JNIEnv *env) {
    this->api_ = api;
    this->env_ = env;

    // Create two singlton instances for classes Context and ConfigBridge
    instance_.reset(this);
    ConfigImpl::Init();
    LOGD("Vector Zygisk module loaded");
}

void VectorModule::preAppSpecialize(zygisk::AppSpecializeArgs *args) {
    // Reset state for this new process fork.
    should_inject_ = false;
    is_manager_app_ = false;

    // --- Manager App Special Handling ---
    // We identify our manager app by a special UID and
    // grant it internet permissions by adding it to the INET group.
    if (args->uid == kHostPackageUid) {
        lsplant::JUTFString nice_name_str(env_, args->nice_name);
        if (nice_name_str.get() == std::string(kManagerPackageName)) {
            LOGI("Manager app detected. Granting internet permissions.");
            is_manager_app_ = true;

            // Add GID_INET to the GID list.
            int original_gids_count = env_->GetArrayLength(args->gids);
            jintArray new_gids = env_->NewIntArray(original_gids_count + 1);
            if (env_->ExceptionCheck()) {
                LOGE("Failed to create new GID array for manager.");
                env_->ExceptionClear();  // Clear exception to prevent a crash.
                return;
            }

            jint *gids_array = env_->GetIntArrayElements(args->gids, nullptr);
            env_->SetIntArrayRegion(new_gids, 0, original_gids_count, gids_array);
            env_->ReleaseIntArrayElements(args->gids, gids_array, JNI_ABORT);

            jint inet_gid = GID_INET;
            env_->SetIntArrayRegion(new_gids, original_gids_count, 1, &inet_gid);

            // The new array is only seen by the native specialization, which calls setgroups().
            // Once it returns, Zygote#forkAndSpecialize keeps using the array it passed in:
            //
            //   NetworkUtils.setAllowNetworkingForProcess(containsInetGid(gids));
            //
            // That flag lives in libnetd_client and gates the whole process: without it,
            // socket() and dns_open_proxy() fail with EPERM no matter which groups we really
            // belong to. So overwrite the first entry of the original array as well, to make
            // containsInetGid() see the INET group. Dropping this slot is harmless: the array
            // has no further use once specialization is done.
            if (original_gids_count > 0) {
                env_->SetIntArrayRegion(args->gids, 0, 1, &inet_gid);
            }

            args->nice_name = env_->NewStringUTF(VECTOR_STR(INJECTED_PACKAGE_NAME));
            args->gids = new_gids;
        }
    }

    IPCBridge::GetInstance().Initialize(env_);

    // --- Injection Decision Logic ---
    // Determine if the current process is a valid target for injection.
    lsplant::JUTFString nice_name_str(env_, args->nice_name);

    // An app without a data directory cannot be a target.
    if (!args->app_data_dir) {
        LOGD("Skipping injection for '{}': no app_data_dir.", nice_name_str.get());
        return;
    }

    // Child Zygotes are specialized zygotes for apps like WebView and are not targets.
    if (args->is_child_zygote && *args->is_child_zygote) {
        LOGD("Skipping injection for '{}': is a child zygote.", nice_name_str.get());
        return;
    }

    // Skip isolated processes, which are heavily sandboxed.
    const uid_t app_id = args->uid % PER_USER_RANGE;
    if ((app_id >= FIRST_ISOLATED_UID && app_id <= LAST_ISOLATED_UID) ||
        (app_id >= FIRST_APP_ZYGOTE_ISOLATED_UID && app_id <= LAST_APP_ZYGOTE_ISOLATED_UID) ||
        app_id == SHARED_RELRO_UID) {
        LOGV("Skipping injection for '{}': is an isolated process (UID: {}).", nice_name_str.get(),
             app_id);
        return;
    }

    // If we passed all checks, mark this process for injection.
    should_inject_ = true;
    LOGV("Process '{}' (UID: {}) is marked for injection.", nice_name_str.get(), args->uid);
}

void VectorModule::postAppSpecialize(const zygisk::AppSpecializeArgs *args) {
    if (!should_inject_) {
        SetAllowUnload(true);  // Not a target, allow module to be unloaded.
        return;
    }

    if (is_manager_app_) {
        args->nice_name = env_->NewStringUTF(kManagerPackageName);
    }

    // --- Framework Injection ---
    lsplant::JUTFString nice_name_str(env_, args->nice_name);
    LOGD("Asking the daemon about '{}'.", nice_name_str.get());

    auto &ipc_bridge = IPCBridge::GetInstance();
    auto binder = ipc_bridge.RequestAppBinder(env_, args->nice_name);
    if (!binder) {
        // Usually because nothing has it in scope, but the daemon may also not be up yet or have
        // registered this process already. Only it knows which, and it logs the reason itself.
        LOGD("Not injecting '{}': the daemon has no binder for it.", nice_name_str.get());
        SetAllowUnload(true);
        return;
    }

    // Fetch resources from the manager service.
    auto [dex_fd, dex_size] = ipc_bridge.FetchFrameworkDex(env_, binder.get());
    if (dex_fd < 0) {
        LOGE("Failed to fetch framework DEX for '{}'.", nice_name_str.get());
        SetAllowUnload(true);
        return;
    }

    auto obfs_map = ipc_bridge.FetchObfuscationMap(env_, binder.get());
    ConfigBridge::GetInstance()->obfuscation_map(std::move(obfs_map));

    {
        PreloadedDex dex(dex_fd, dex_size);
        this->LoadDex(env_, std::move(dex));
    }
    close(dex_fd);  // The FD is duplicated by mmap, we can close it now.

    // Initialize ART hooks via the native library.
    this->InitArtHooker(env_, init_info_);
    // Initialize JNI hooks via the native library.
    this->InitHooks(env_);
    // Find the Java entrypoint.
    this->SetupEntryClass(env_);

    // CAREME: same in-place idmap exec that kills system_server also hits injected app processes
    // (verifySystemIdmaps -> exit(1) -> __cxa_finalize runs our fork-unsafe static dtors ->
    // je_free SIGSEGV) once a resource-hooking module in their scope makes forkCommon touch the
    // system resources. Neutralise it here too, before modules load.
    caremedbg::install_idmap_neutralizer();

    // Hand off control to the Java side of the framework.
    bool entered = this->FindAndCall(
        env_, "forkCommon", "(ZZLjava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V",
        JNI_FALSE, JNI_FALSE, args->nice_name, args->app_data_dir, binder.get(), is_manager_app_);

    if (entered) {
        LOGV("Injected Vector framework into '{}'.", nice_name_str.get());
    } else {
        LOGE("Framework entry failed in '{}'; this process runs without Xposed.",
             nice_name_str.get());
    }
    // Unconditionally: the ART and JNI hooks were installed before the entry ran, and their
    // trampolines point into this library. Letting it be unloaded now would leave them dangling.
    SetAllowUnload(false);
}

void VectorModule::preServerSpecialize(zygisk::ServerSpecializeArgs *args) {
    // The system server is always a target for injection.
    should_inject_ = true;
    LOGI("System server process detected. Marking for injection.");

    // Initialize our IPC bridge singleton.
    IPCBridge::GetInstance().Initialize(env_);
}

void VectorModule::postServerSpecialize(const zygisk::ServerSpecializeArgs *args) {
    if (!should_inject_) {
        SetAllowUnload(true);
        return;
    }

    LOGD("Attempting injection into system_server.");
    caremedbg::vlog("[vdbg-native] postServerSpecialize enter");
    caremedbg::install_exit_hooks();

    // --- Device-Specific Workaround ---
    // Some ZTE devices require argv[0] to be explicitly set to "system_server"
    // for certain services to function correctly after modification.
    if (__system_property_find("ro.vendor.product.ztename")) {
        LOGV("Applying ZTE-specific workaround: setting argv[0] to system_server.");
        auto process_class = lsplant::ScopedLocalRef(env_, env_->FindClass("android/os/Process"));
        if (process_class) {
            auto set_argv0_mid =
                env_->GetStaticMethodID(process_class.get(), "setArgV0", "(Ljava/lang/String;)V");
            auto name_str = lsplant::ScopedLocalRef(env_, env_->NewStringUTF("system_server"));
            if (set_argv0_mid && name_str) {
                env_->CallStaticVoidMethod(process_class.get(), set_argv0_mid, name_str.get());
            }
        }
        if (env_->ExceptionCheck()) {
            LOGW("Exception occurred during ZTE workaround.");
            env_->ExceptionClear();
        }
    }

    // --- Framework Injection for System Server ---
    auto &ipc_bridge = IPCBridge::GetInstance();
    std::string bridgeServiceName = "serial";
    bool is_late_inject = (args->runtime_flags & RuntimeFlags::LATE_INJECT) != 0;
    if (is_late_inject) bridgeServiceName = "serial_vector";
    auto system_binder = ipc_bridge.RequestSystemServerBinder(env_, bridgeServiceName);
    if (!system_binder) {
        LOGE("Failed to get system server IPC binder. Aborting injection.");
        SetAllowUnload(true);  // Allow unload on failure.
        return;
    }

    auto manager_binder =
        ipc_bridge.RequestManagerBinderFromSystemServer(env_, system_binder.get());

    // Use either the direct manager binder if available,
    // otherwise proxy through the system binder.
    jobject effective_binder = manager_binder ? manager_binder.get() : system_binder.get();

    auto [dex_fd, dex_size] = ipc_bridge.FetchFrameworkDex(env_, effective_binder);
    if (dex_fd < 0) {
        LOGE("Failed to fetch framework DEX for system_server.");
        SetAllowUnload(true);
        return;
    }

    auto obfs_map = ipc_bridge.FetchObfuscationMap(env_, effective_binder);
    ConfigBridge::GetInstance()->obfuscation_map(std::move(obfs_map));

    {
        PreloadedDex dex(dex_fd, dex_size);
        this->LoadDex(env_, std::move(dex));
    }
    close(dex_fd);

    ipc_bridge.HookBridge(env_);

    this->InitArtHooker(env_, init_info_);
    this->InitHooks(env_);
    this->SetupEntryClass(env_);

    auto system_name = lsplant::ScopedLocalRef(env_, env_->NewStringUTF("system"));
    caremedbg::vlog("[vdbg-native] before FindAndCall(forkCommon)");
    bool entered = this->FindAndCall(
        env_, "forkCommon", "(ZZLjava/lang/String;Ljava/lang/String;Landroid/os/IBinder;)V",
        JNI_TRUE, is_late_inject, system_name.get(), nullptr, manager_binder.get(),
        is_manager_app_);
    caremedbg::vlog("[vdbg-native] after FindAndCall(forkCommon)");

    if (entered) {
        LOGI("Injected Vector framework into system_server.");
    } else {
        LOGE("Framework entry failed in system_server; it runs without Xposed.");
    }
    // See postAppSpecialize: the hooks outlive a failed entry, so the library must stay.
    SetAllowUnload(false);
}

void VectorModule::SetAllowUnload(bool unload) {
    if (api_ && unload) {
        LOGD("Allowing Zygisk to unload module library.");
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);

        // Release the pointer from the unique_ptr's control. This prevents the
        // static unique_ptr's destructor from calling delete on our object, which
        // would cause a double-free when the Zygisk framework cleans up.
        if (instance_.release() != nullptr) {
            LOGD("Module context singleton released.");
        }
    } else {
        LOGD("Preventing Zygisk from unloading module library.");
    }
}

}  // namespace vector::native::module

// =========================================================================================
// Zygisk Module Registration
// =========================================================================================
REGISTER_ZYGISK_MODULE(vector::native::module::VectorModule);
