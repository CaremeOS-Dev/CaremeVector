cmake_minimum_required(VERSION 3.10)

project(zygisk)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# CaremeOS ART 8.1: on-device one-target bisection showed that optimizing only lsplant_static at
# -O2 is sufficient to corrupt the native entry of the unrelated WifiNative.registerNatives
# ArtMethod before Wi-Fi starts; keeping LSPlant at -O0 while every other native target remains on
# normal RelWithDebInfo codegen boots cleanly. Restrict the workaround to that one target.
option(CAREMEOS_SAFE_LSPLANT "Compile LSPlant without optimization on CaremeOS ART 8.1" OFF)

add_subdirectory(${VECTOR_ROOT}/native native)

add_library(${PROJECT_NAME} SHARED module.cpp ipc_bridge.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (CAREMEOS_SAFE_LSPLANT)
    # A target option is emitted after CMake's global RelWithDebInfo -O2, so this final -O0 wins for
    # LSPlant alone. Vector native, IPCBridge, Dobby, dex_builder and other dependencies stay O2.
    target_compile_options(lsplant_static PRIVATE -O0)
endif()

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
