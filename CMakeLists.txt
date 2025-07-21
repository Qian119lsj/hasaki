cmake_minimum_required(VERSION 3.16)

project(hasaki VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Core Network)

set(SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/packet_forwarder.cpp
    src/portprocessmonitor.cpp
    src/appsettings.cpp
    src/settingsdialog.cpp
    src/utils.cpp
    src/proxy_server.cpp
    src/socks5_client.cpp
    src/endpoint_mapper.cpp
    src/socks5serverdialog.cpp
    src/delayed_delete_manager.cpp
    src/udp_packet_injector.cpp
    src/udptestdialog.cpp
    src/udp_session_manager.cpp
    src/tcp_session_manager.cpp
)

file(GLOB_RECURSE UIS "src/*.ui")

set(HEADERS
    include/hasaki/mainwindow.h
    include/hasaki/packet_forwarder.h
    include/hasaki/portprocessmonitor.h
    include/hasaki/appsettings.h
    include/hasaki/settingsdialog.h
    include/hasaki/utils.h
    include/hasaki/proxy_server.h
    include/hasaki/socks5_client.h
    include/hasaki/endpoint_mapper.h
    include/hasaki/socks5serverdialog.h
    include/hasaki/udp_packet_injector.h
    include/hasaki/udptestdialog.h
    include/hasaki/udp_session_manager.h
    include/hasaki/tcp_session_manager.h
)

# Windows资源文件和清单
if(WIN32)
    # 禁用默认清单生成
    if(MSVC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
    endif()
    
    # 配置清单文件
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/hasaki.manifest"
        "${CMAKE_CURRENT_BINARY_DIR}/hasaki.manifest"
        COPYONLY
    )
    
    # 创建RC文件
    set(RC_FILE "${CMAKE_CURRENT_BINARY_DIR}/hasaki.rc")
    file(WRITE "${RC_FILE}" "#include <windows.h>\n")
    file(APPEND "${RC_FILE}" "1 24 \"${CMAKE_CURRENT_BINARY_DIR}/hasaki.manifest\"\n")
    
    set(PLATFORM_SPECIFIC_FILES ${RC_FILE})
endif()

qt_add_executable(hasaki
    ${SOURCES}
    ${UIS}
    ${HEADERS}
    ${PLATFORM_SPECIFIC_FILES}
)


target_link_libraries(hasaki PRIVATE
    Qt::Widgets
    Qt::Network
    ws2_32
)


set(WINDIVERT_DIR ${CMAKE_SOURCE_DIR}/third_party/windivert)
set(WINDIVERT_INCLUDE_DIR ${WINDIVERT_DIR}/include)
set(WINDIVERT_LIBRARY ${WINDIVERT_DIR}/lib/WinDivert.lib)

target_include_directories(hasaki PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${WINDIVERT_INCLUDE_DIR}
)

target_link_libraries(hasaki PRIVATE ${WINDIVERT_LIBRARY})

set(WINDIVERT_LIBRARY_DIR ${WINDIVERT_DIR}/lib)
add_custom_command(
    TARGET hasaki POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_LIBRARY_DIR}/WinDivert.dll"
        "$<TARGET_FILE_DIR:hasaki>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WINDIVERT_LIBRARY_DIR}/WinDivert64.sys"
        "$<TARGET_FILE_DIR:hasaki>"
    COMMENT "Copying WinDivert runtime files..."
)

include(GNUInstallDirs)
install(TARGETS hasaki
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

