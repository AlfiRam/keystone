# examples/sealPointWiseEnclave/CMakeLists.txt
set(eapp_bin sealPointWiseEnclave)
set(eapp_src main.cpp)
set(host_bin sealPointWiseEnclave-runner)
set(host_src host.cpp)
set(package_name "sealPointWiseEnclave.ke")
set(package_script "./sealPointWiseEnclave-runner sealPointWiseEnclave eyrie-rt loader.bin")
set(eyrie_plugins "io_syscall linux_syscall env_setup")

# seal

# Set the path to the SEAL library and its dependencies
set(SEAL_LIBRARY_PATH /home/malfiram/keystone/build-generic64/buildroot.build/build/seal-4.1.2/buildroot-build/lib/libseal-4.1.a)
set(SEAL_C_LIBRARY_PATH /home/malfiram/keystone/build-generic64/buildroot.build/build/seal-4.1.2/buildroot-build/lib/libsealc-4.1.a)
set(SEAL_INCLUDE_DIR /home/malfiram/keystone/build-generic64/buildroot.build/per-package/seal/host/riscv64-buildroot-linux-gnu/sysroot/usr/include/SEAL-4.1)

# eapp
add_executable(${eapp_bin} ${eapp_src})
target_include_directories(${eapp_bin} PRIVATE ${SEAL_INCLUDE_DIR})
target_link_libraries(${eapp_bin} "-static" ${SEAL_C_LIBRARY_PATH} ${SEAL_LIBRARY_PATH})

# host
add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})

# add target for Eyrie runtime (see keystone.cmake)
set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)
add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)