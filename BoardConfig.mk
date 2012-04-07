# Copyright (C) 2010 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# This file sets variables that control the way modules are built
# thorughout the system. It should not be used to conditionally
# disable makefiles (the proper mechanism to control what gets
# included in a build is to use PRODUCT_PACKAGES in a product
# definition file).
#

# WARNING: This line must come *before* including the proprietary
# variant, so that it gets overwritten by the parent (which goes
# against the traditional rules of inheritance).
# The proprietary variant sets USE_CAMERA_STUB := false, this way
# we use the camera stub when the vendor tree isn't present, and
# the true camera library when the vendor tree is available.  Similarly,
# we set USE_PROPRIETARY_AUDIO_EXTENSIONS to true in the proprietary variant as
# well.
USE_CAMERA_STUB := true

# Use screencap to capture frame buffer for ddms
BOARD_USE_SCREENCAP := true

# Use a smaller subset of system fonts to keep image size lower
SMALLER_FONT_FOOTPRINT := true

# inherit from the proprietary version
# needed for BP-flashing updater extensions
-include vendor/moto/stingray/BoardConfigVendor.mk

TARGET_BOARD_PLATFORM := tegra

TARGET_CPU_ABI := armeabi-v7a
TARGET_CPU_ABI2 := armeabi
TARGET_CPU_SMP := true
TARGET_ARCH_VARIANT_CPU := cortex-a9
TARGET_ARCH_VARIANT_FPU := vfpv3-d16
TARGET_ARCH_VARIANT := armv7-a
ARCH_ARM_HAVE_TLS_REGISTER := true

TARGET_USERIMAGES_USE_EXT4 := true

BOARD_SYSTEMIMAGE_PARTITION_SIZE := 251658240
BOARD_USERDATAIMAGE_PARTITION_SIZE := 31399067648
BOARD_FLASH_BLOCK_SIZE := 4096

# OLD Wifi related defines
#BOARD_WPA_SUPPLICANT_DRIVER := AWEXT
#WPA_SUPPLICANT_VERSION      := VER_0_8_X
WPA_SUPPLICANT_VERSION      := VER_0_6_ATHEROS
#BOARD_WLAN_DEVICE           := bcmdhd
#WIFI_DRIVER_MODULE_PATH     := "/system/lib/hw/wlan/ar6000.ko"
#WIFI_DRIVER_MODULE_NAME     := "ar6000"

# Wifi related defines
WPA_SUPPLICANT_VERSION := VER_0_8_X
BOARD_WPA_SUPPLICANT_DRIVER := WEXT
BOARD_WPA_SUPPLICANT_PRIVATE_LIB := lib_driver_cmd_atheros
BOARD_HOSTAPD_DRIVER := AR6000
BOARD_HOSTAPD_PRIVATE_LIB :=
BOARD_WLAN_DEVICE := ar6002
WIFI_DRIVER_MODULE_PATH := "/system/lib/hw/wlan/ar6000.ko"
WIFI_DRIVER_MODULE_NAME	 := "ar6000"
WIFI_DRIVER_MODULE_ARG	 := ""
WIFI_DRIVER_LOADER_DELAY	:= 3000000 



BOARD_USES_GENERIC_AUDIO := false
BOARD_HAVE_BLUETOOTH := true
BOARD_HAVE_GPS := true
USE_OPENGL_RENDERER := true
BOARD_EGL_CFG := device/moto/wingray/egl.cfg
BOARD_HDMI_MIRROR_MODE := Scale
BOARD_USES_OVERLAY := true

ifneq ($(HAVE_NVIDIA_PROP_SRC),false)
# needed for source compilation of nvidia libraries
-include vendor/nvidia/proprietary_src/build/definitions.mk
-include vendor/nvidia/build/definitions.mk
endif

TARGET_RECOVERY_UI_LIB := librecovery_ui_stingray
TARGET_RECOVERY_PRE_COMMAND := "setrecovery boot-recovery recovery"

# Avoid the generation of ldrcc instructions
NEED_WORKAROUND_CORTEX_A9_745320 := true

# Skip droiddoc build to save build time
BOARD_SKIP_ANDROID_DOC_BUILD := true

# Setting this to avoid boot locks on the system from using the "misc" partition.
BOARD_HAS_NO_MISC_PARTITION := true

PRODUCT_CHARACTERISTICS := tablet
BOARD_USES_SECURE_SERVICES := true
