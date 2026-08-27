cmake_minimum_required(VERSION 3.10)

project(zygisk)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# CaremeOS ART 8.1: the optimized native build corrupts the native entry stored in an unrelated
# ArtMethod (WifiNative.registerNatives) before Wi-Fi starts. A Debug-native/Release-Java hybrid is
# stable on-device, which isolates the fault to this native tree. Keep the production Java/APK
# variants and symbol stripping, but use conservative native codegen until the exact optimizer UB
# (Dobby -O3 vs C++ RelWithDebInfo -O2) is narrowed further.
option(CAREMEOS_SAFE_NATIVE "Use conservative native codegen for CaremeOS ART 8.1" OFF)
if (CAREMEOS_SAFE_NATIVE)
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O0 -g -DNDEBUG" CACHE STRING "" FORCE)
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O0 -g -DNDEBUG" CACHE STRING "" FORCE)
    set(DOBBY_DEBUG ON CACHE BOOL "" FORCE)
endif()

add_subdirectory(${VECTOR_ROOT}/native native)

add_library(${PROJECT_NAME} SHARED module.cpp ipc_bridge.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC include)

target_link_libraries(${PROJECT_NAME} native log)

if (DEFINED DEBUG_SYMBOLS_PATH)
    message(STATUS "Debug symbols will be placed at ${DEBUG_SYMBOLS_PATH}")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory ${DEBUG_SYMBOLS_PATH}/${ANDROID_ABI}
            COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:${PROJECT_NAME}>
            ${DEBUG_SYMBOLS_PATH}/${ANDROID_ABI}/${PROJECT_NAME}.debug
            COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:${PROJECT_NAME}>
            COMMAND ${CMAKE_OBJCOPY} --add-gnu-debuglink ${DEBUG_SYMBOLS_PATH}/${ANDROID_ABI}/${PROJECT_NAME}.debug
            $<TARGET_FILE:${PROJECT_NAME}>)
endif()
