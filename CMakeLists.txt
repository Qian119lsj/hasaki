cmake_minimum_required(VERSION 3.24)

project(hasaki VERSION 0.1 LANGUAGES CXX)

find_package(Qt6 CONFIG REQUIRED COMPONENTS Widgets Core Network)
message(STATUS "Found Qt version: ${Qt6_VERSION}")

qt_standard_project_setup()

set(SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/packet_forwarder.cpp
    "src/port_process_monitor.cpp"
    "src/app_settings.cpp"
    "src/settings_dialog.cpp"
    src/utils.cpp
    src/proxy_server.cpp
    "src/socks5client.cpp"
    src/endpoint_mapper.cpp
    src/socks5serverdialog.cpp
    src/delayed_delete_manager.cpp
    src/udp_packet_injector.cpp
    src/udptestdialog.cpp
    src/udp_session_manager.cpp
    src/tcp_session_manager.cpp
    src/console_manager.cpp
)

file(GLOB_RECURSE UIS "src/*.ui")

set(HEADERS
    include/hasaki/mainwindow.h
    include/hasaki/packet_forwarder.h
    "include/hasaki/port_process_monitor.h"
    "include/hasaki/app_settings.h"
    include/hasaki/settingsdialog.h
    include/hasaki/utils.h
    include/hasaki/proxy_server.h
    "include/hasaki/socks5_client.h"
    include/hasaki/endpoint_mapper.h
    include/hasaki/socks5serverdialog.h
    include/hasaki/udp_packet_injector.h
    include/hasaki/udptestdialog.h
    include/hasaki/udp_session_manager.h
    include/hasaki/tcp_session_manager.h
    "include/hasaki/console_manager.h"
)

add_executable(hasaki WIN32
    ${SOURCES}
    ${HEADERS}
    ${UIS}
)

set(WINDIVERT_DIR ${CMAKE_SOURCE_DIR}/third_party/windivert)
target_include_directories(hasaki PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${WINDIVERT_DIR}/include
)
target_link_libraries(hasaki PRIVATE ${WINDIVERT_DIR}/lib/WinDivert.lib)
add_custom_command(
    TARGET hasaki POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/lib/WinDivert.dll"
        "$<TARGET_FILE_DIR:hasaki>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_DIR}/lib/WinDivert64.sys"
        "$<TARGET_FILE_DIR:hasaki>"
    COMMENT "Copying WinDivert runtime files..."
)

if(CMAKE_EXPORT_COMPILE_COMMANDS)
    add_custom_target(
        copy_compile_commands ALL
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_BINARY_DIR}/compile_commands.json"
                "${CMAKE_SOURCE_DIR}/compile_commands.json"
        COMMENT "Copying compile_commands.json to root directory..."
    )
endif()

# Windows资源文件和清单
if(WIN32)
    # 根据编译器类型设置正确的UTF-8源文件编码标志
    if(MSVC)
        # MSVC 编译器的标志
        add_compile_options(/MP)
        target_compile_options(hasaki PRIVATE /utf-8)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # Clang/GCC 风格编译器的标志
        target_compile_options(hasaki PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
    endif()

    # 生成器区分：
    # - Visual Studio 生成器：使用 VS_APPLICATION_MANIFEST 属性
    # - 其他生成器（如 Ninja/ClangCL）：使用链接器 /MANIFESTUAC 直接注入 UAC，避免与自动生成的清单重复
    if(CMAKE_GENERATOR MATCHES "Visual Studio")
        set_target_properties(hasaki PROPERTIES
            VS_APPLICATION_MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/src/hasaki.manifest"
        )
    else()
        # 非 VS 生成器：根据前端区分参数传递方式
        if(CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
            # clang-cl / msvc 前端：直接使用 MSVC 风格参数
            target_link_options(hasaki PRIVATE 
                "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
            )
        else()
            # GNU/Clang 前端：通过 -Xlinker 传给链接器，并用 SHELL: 保持整体引号不被拆分
            target_link_options(hasaki PRIVATE 
                "SHELL:-Xlinker /MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
            )
        endif()
    endif()
endif()

target_link_libraries(hasaki PRIVATE
    Qt::Widgets
    Qt::Network
    ws2_32
)


# 安装可执行文件
install(TARGETS hasaki
    RUNTIME DESTINATION bin
)

# 安装 WinDivert runtime
install(FILES
    "${WINDIVERT_DIR}/lib/WinDivert.dll"
    "${WINDIVERT_DIR}/lib/WinDivert64.sys"
    DESTINATION bin
)

# 根据构建类型选择 Qt bin 目录
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(QT_BUILD_TYPE_DIR "debug")
else()
    set(QT_BUILD_TYPE_DIR "release")
endif()

# 自动调用 windeployqt
if(WIN32)
    add_custom_command(TARGET hasaki POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Debug info:"
        COMMAND ${CMAKE_COMMAND} -E echo "Qt6_DIR=${Qt6_DIR}"
        COMMAND ${CMAKE_COMMAND} -E echo "windeployqt=$<TARGET_FILE:Qt6::windeployqt>"
        COMMAND ${CMAKE_COMMAND} -E echo "target_dir=$<TARGET_FILE_DIR:hasaki>"
        COMMAND ${CMAKE_COMMAND} -E echo "target_exe=$<TARGET_FILE:hasaki>"
        COMMAND ${CMAKE_COMMAND} -E echo "target_exe=$<TARGET_FILE:hasaki>"
        COMMAND $<TARGET_FILE:Qt6::windeployqt>
                "--${QT_BUILD_TYPE_DIR}"
                "$<TARGET_FILE:hasaki>"
        COMMENT "Running windeployqt for ${CMAKE_BUILD_TYPE} build..."
    )

    install(CODE "
        message(STATUS \"Running windeployqt on installed executable...\")
        execute_process(
            COMMAND $<TARGET_FILE:Qt6::windeployqt>
                    \"--${QT_BUILD_TYPE_DIR}\" 
                    \"\${CMAKE_INSTALL_PREFIX}/bin/hasaki.exe\"
            WORKING_DIRECTORY \"\${CMAKE_INSTALL_PREFIX}/bin\"
            RESULT_VARIABLE deploy_result
        )
        if(NOT deploy_result EQUAL 0)
            message(WARNING \"windeployqt failed with result: \${deploy_result}\")
        endif()
    ")
endif()
