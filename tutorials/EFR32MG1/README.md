# Basic Tutorial – EFR32MG1 Blink

## Source

This firmware is built from the public repository [lzptr/efr32\_base](https://github.com/lzptr/efr32_base).
Starting from the repository’s default branch, the following patch was applied to `CMakeLists.txt` to target an EFR32
MG1 device and a locally installed GNU ARM toolchain:

```diff
@@
-    set( ARM_TOOLCHAIN_PATH /opt/toolchain/gcc-arm-none-eabi-10.3-2021.10/ )
+    set( ARM_TOOLCHAIN_PATH /usr/ )
@@
-    set(EFR32_DEVICE EFR32MG12P332F1024GL125)  # Sets device / used to locate HAL files
+    set(EFR32_DEVICE EFR32MG1P132F256GM32)     # Sets device / used to locate HAL files
     set(BOARD BRD4166A)                     # Thunderboard Sense 2
```

To build the firmware, follow the instructions in the [lzptr/efr32\_base](https://github.com/lzptr/efr32_base)
repository.

For convenience, the pre-build binary is available here: [EFR32MG1_blink_debug](EFR32MG1_blink_debug)

## Tutorial