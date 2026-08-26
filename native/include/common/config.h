#pragma once

/**
 * @file config.h
 * @brief Compile-time constants, version information, and platform-specific configurations.
 */

namespace vector::native {

[[nodiscard]] constexpr bool IsDebugBuild() {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

/// A compile-time constant indicating if this is a debug build.
inline constexpr bool kIsDebugBuild = IsDebugBuild();

/**
 * @def LP_SELECT(lp32, lp64)
 * @brief A preprocessor macro to select a value based on the architecture.
 * @param lp32 The value to use on 32-bit platforms.
 * @param lp64 The value to use on 64-bit platforms.
 */
#if defined(__LP64__)
#define LP_SELECT(lp32, lp64) lp64
#else
#define LP_SELECT(lp32, lp64) lp32
#endif

// Stringify a -D macro value regardless of whether the build system's quoting survived.
// The Gradle -> CMake -> ninja -> cmd pipeline on Windows strips embedded quotes, so a
// plain `const char* s = VERSION_NAME;` sees a bare token (2.2) instead of "2.2".
#define VECTOR_STR_(x) #x
#define VECTOR_STR(x) VECTOR_STR_(x)

/// The filename of the core Android Runtime (ART) library.
inline constexpr auto kArtLibraryName = "libart.so";

/// The filename of the Android Binder library.
inline constexpr auto kBinderLibraryName = "libbinder.so";

/// The filename of the Android Framework library.
inline constexpr auto kFrameworkLibraryName = "libandroidfw.so";

/// The path to the dynamic linker.
inline constexpr auto kLinkerPath = "/linker";

/// The version code of the library, populated by the build system.
const int kVersionCode = VERSION_CODE;

/// The version name of the library, populated by the build system.
const char *const kVersionName = VECTOR_STR(VERSION_NAME);

}  // namespace vector::native
