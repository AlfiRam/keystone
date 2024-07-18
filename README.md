# FHE in Keystone

## Important Notice
**Do not clone this repo directly.** It will result in an unsuccessful build. This repository is for viewing purposes only, showcasing changes and additions to the original Keystone repository.

## Prerequisites
Before exploring the new changes, directories, and files, it's crucial to set up Keystone on QEMU. Follow the official documentation: [Keystone QEMU Setup](https://docs.keystone-enclave.org/en/latest/Getting-Started/QEMU-Setup-Repository.html). A summary of the essential instructions taken from that documentation is also included in the instructions below:

## Setup Instructions

1. Clone the Keystone repository with submodules:
   ```
   git clone --recurse-submodules https://github.com/keystone-enclave/keystone.git
   ```

2. Install required packages:
   ```
   sudo apt update
   sudo apt install autoconf automake autotools-dev bc bison build-essential curl expat jq libexpat1-dev flex gawk gcc git gperf libgmp-dev libmpc-dev libmpfr-dev libtool texinfo tmux patchutils zlib1g-dev wget bzip2 patch vim-common lbzip2 python3 pkg-config libglib2.0-dev libpixman-1-dev libssl-dev screen device-tree-compiler expect makeself unzip cpio rsync cmake ninja-build p7zip-full
   ```

3. Build all components:
   ```
   make -j$(nproc)
   ```

4. Add the "seal" directory to `buildroot/package/`

5. Create `Config.in` file in the new `buildroot/package/seal` directory with:
   ```
   menuconfig BR2_PACKAGE_SEAL
     bool "seal"
     help
       Microsoft SEAL is an open-source homomorphic encryption library.
       https://github.com/microsoft/Microsoft-SEAL
   ```

6. Create `seal.mk` file in the new `buildroot/package/seal` directory with the following content:
   ```makefile
   ################################################################################
   #
   # seal
   #
   ################################################################################

   SEAL_VERSION = 4.1.2
   SEAL_SITE = $(call github,microsoft,SEAL,v$(SEAL_VERSION))
   SEAL_INSTALL_STAGING = YES
   SEAL_SUPPORTS_IN_SOURCE_BUILD = NO
   SEAL_CONF_OPTS = \
       -DSEAL_BUILD_DEPS=ON \
       -DSEAL_BUILD_EXAMPLES=OFF \
       -DSEAL_BUILD_TESTS=OFF \
       -DSEAL_USE_ZSTD=OFF \
       -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF \
       -DSEAL_USE_MSGSL=OFF \
       -DSEAL_USE_ZLIB=OFF \
       -DBUILD_SHARED_LIBS=OFF \
       -DSEAL_BUILD_SEAL_C=ON \
       -DSEAL_BUILD_STATIC_SEAL_C=ON

   $(eval $(cmake-package))
   ```

7. Modify `buildroot/package/Config.in`:
   Add a "SEAL" menu under the "Libraries" category. It should look like this:
   ```
   menu "Libraries"

   menu "SEAL"
       source "package/seal/Config.in"
   endmenu

   menu "Audio/Sound"
       source "package/alsa-lib/Config.in"
       source "package/alsa-plugins/Config.in"
       source "package/alure/Config.in"
       source "package/aubio/Config.in"
   # ... (rest of the file)
   ```

8. Configure buildroot:
   ```
   make buildroot-configure
   ```

9. Enable SEAL in the buildroot configuration:
   Navigate to Target Packages -> Libraries -> SEAL -> [*] seal

10. Save and exit buildroot configuration

11. Rebuild all Keystone components:
    ```
    make -j$(nproc)
    ```

12. The previous command will result in downloading and building the SEAL package. Note the locations of SEAL's static library and include directory, as they will be used in the CMakeLists files of our FHE-Keystone apps:
    - Static library: usually found at `buildroot.build/per-package/seal/target/usr/lib/libseal-4.1.a`
    - Include directory: may be found at `build-generic64/buildroot.build/per-package/seal/host/riscv64-buildroot-linux-gnu/sysroot/usr/include/SEAL-4.1`

13. I have added several FHE demonstrations and they are available in this repo's `examples` directory:
    - `examples/sealdemoNonEnclave`
    - `examples/sealMatrixAddEnclave`
    - `examples/sealMatrixMulEnclave`
    - `examples/sealMatrixRotationEnclave`
    - `examples/sealPointWiseEnclave`

    Note: Some implementations may require further refinement

14. Rebuild the examples component:
    ```
    BUILDROOT_TARGET=keystone-examples-dirclean make -j$(nproc)
    ```

15. Add the following code to `runtime/call/syscall.c` under `#ifdef USE_LINUX_SYSCALL`:

    ```c
    // ... existing code ...

    case(SYS_set_tid_address):
      ret = linux_set_tid_address((int*) arg0);
      break;

    // Add the following three lines:
    case(SYS_futex):
      ret = 0;
      break;
    
    case(SYS_brk):
      ret = syscall_brk((void*) arg0);
      break;

    // ... rest of the existing code ...
    ```

16. Rebuild the runtime component:
    ```
    BUILDROOT_TARGET=keystone-runtime-dirclean make -j$(nproc)
    ```

17. Rebuild all components:
    ```
    make -j$(nproc)
    ```

## Running the Environment

18. Start QEMU:
    ```
    make run
    ```

19. Login as `root` with the password `sifive`
    ```
    buildroot login: root
    Password: sifive
    ```
      
21. In QEMU, start the Keystone driver:
    ```
    modprobe keystone-driver
    ```

22. Navigate to the examples directory:
    ```
    cd /usr/share/keystone/examples/
    ```

21. Run your chosen program from the examples.

## Notes
- Ongoing research and efforts are being made to improve the FHE implementations.
- Please refer to the individual example directories for specific details on each FHE operation demonstration.
