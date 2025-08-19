# =============================================================================
# LLVM/Clang 工具链配置文件
#
# 用法: 在 CMakePresets.json 或命令行中通过
#       -DCMAKE_TOOLCHAIN_FILE=<path-to-this-file> 来指定
# =============================================================================

# 1. 目标系统
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

find_program(CMAKE_C_COMPILER clang)
find_program(CMAKE_CXX_COMPILER clang++)

# 2. 指定编译器
# !! 重要 !!: 请将这里的路径修改为您系统中 LLVM 的实际安装路径。
# set(CMAKE_C_COMPILER       "H:/Program Files/LLVM/bin/clang.exe" CACHE FILEPATH "C compiler")
# set(CMAKE_CXX_COMPILER     "H:/Program Files/LLVM/bin/clang++.exe" CACHE FILEPATH "C++ compiler")

# 3. (推荐) 指定链接器为 LLD 以获得最佳性能
# set(CMAKE_LINKER           "H:/Program Files/LLVM/bin/lld.exe" CACHE FILEPATH "The linker")
find_program(CMAKE_LINKER lld-link)

find_program(CMAKE_AR llvm-ar)
find_program(CMAKE_RANLIB llvm-ranlib)
