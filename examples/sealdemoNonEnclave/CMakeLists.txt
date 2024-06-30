set(eapp_bin sealdemoNonEnclave)
set(eapp_src main.cpp)
set(package_name "sealdemoNonEnclave.ke")
set(package_script "./sealdemoNonEnclave eyrie-rt loader.bin")
set(eyrie_plugins "io_syscall linux_syscall env_setup")

# Set the path to the SEAL library and include directory
set(SEAL_LIBRARY_PATH /home/malfiram/keystone/build-generic64/buildroot.build/per-package/seal/target/usr/lib/libseal-4.1.a)
set(SEAL_C_LIBRARY_PATH /home/malfiram/keystone/build-generic64/buildroot.build/per-package/seal/target/usr/lib/libsealc-4.1.a)
set(SEAL_INCLUDE_DIR /home/malfiram/keystone/build-generic64/buildroot.build/per-package/seal/host/riscv64-buildroot-linux-gnu/sysroot/usr/include/SEAL-4.1)

# eapp
add_executable(${eapp_bin} ${eapp_src})
target_include_directories(${eapp_bin} PRIVATE ${SEAL_INCLUDE_DIR})
target_link_libraries(${eapp_bin} "-static" ${SEAL_C_LIBRARY_PATH} ${SEAL_LIBRARY_PATH})


# Add target for Eyrie runtime (see keystone.cmake)
set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(${eapp_bin}-eyrie ${eyrie_plugins} ${eyrie_files_to_copy})

# Add target for packaging (see keystone.cmake)
add_keystone_package(${eapp_bin}-package ${package_name} ${package_script} ${eyrie_files_to_copy} ${eapp_bin})
add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# Add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)