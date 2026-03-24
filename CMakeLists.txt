cmake_minimum_required(VERSION 4.0)
project(netpatch)

set(CMAKE_CXX_STANDARD 20)

# 先构建 netpatch
add_executable(netpatch main.cpp)

# 生成 bin -> header
add_custom_command(
        OUTPUT netpatch_bin.h
        COMMAND "C:/Program Files/Git/usr/bin/xxd.exe" -i $<TARGET_FILE:netpatch> > netpatch_bin.h
        DEPENDS netpatch
)
target_link_libraries(netpatch
        PRIVATE
)
add_custom_target(embed_netpatch DEPENDS netpatch_bin.h)
# install 依赖这个 header
add_executable(TrickyNetstatOSS install.cpp netpatch_bin.h)
target_include_directories(TrickyNetstatOSS PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_options(netpatch PRIVATE -static -static-libgcc -static-libstdc++)
target_link_options(TrickyNetstatOSS PRIVATE -static -static-libgcc -static-libstdc++)
add_dependencies(TrickyNetstatOSS embed_netpatch)