LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

bluetoothd_SRC_FILES_17 := bt-av-io.c \
                           bt-core-io.c \
                           bt-hf-io.c \
                           bt-sock-io.c
bluetoothd_SRC_FILES_18 := $(bluetoothd_SRC_FILES_17) \
                           bt-rc-io.c
bluetoothd_SRC_FILES_19 := $(bluetoothd_SRC_FILES_18) \
                           bt-gatt-io.c
bluetoothd_SRC_FILES_20 := $(bluetoothd_SRC_FILES_19)
bluetoothd_SRC_FILES_21 := $(bluetoothd_SRC_FILES_20)
bluetoothd_SRC_FILES_22 := $(bluetoothd_SRC_FILES_21)
bluetoothd_SRC_FILES    := $(bluetoothd_SRC_FILES_$(PLATFORM_SDK_VERSION)) \
                           bt-io.c \
                           bt-proto.c \
                           bt-pdubuf.c \
                           core.c \
                           core-io.c \
                           main.c \
                           sdpsrvc.c \
                           service.c

ifeq ($(strip $(bluetoothd_SRC_FILES_$(PLATFORM_SDK_VERSION))),)
$(error "Please set $$bluetoothd_SRC_FILES_$(PLATFORM_SDK_VERSION) in bluetoothd's makefile.")
endif

ANDROID_VERSION_CONST := $(shell echo $(PLATFORM_VERSION) | awk -F. '{ printf "0x%02d%02d%02d",$$1,$$2,$$3 }')

LOCAL_SRC_FILES := $(bluetoothd_SRC_FILES)
LOCAL_C_INCLUDES := system/libfdio/include
LOCAL_CFLAGS := -DANDROID_VERSION=$(PLATFORM_SDK_VERSION) \
                -DANDROID_VERSION_CONST=$(ANDROID_VERSION_CONST) \
                -Wall -Werror

ifeq ($(strip $(BOARD_BLUETOOTH_BDROID_USE_CAF_EXTENSIONS)),true)
LOCAL_CFLAGS += -DQ_BLUETOOTH=1
endif

LOCAL_SHARED_LIBRARIES := libfdio \
                          libhardware \
                          libhardware_legacy \
                          libcutils \
                          liblog
LOCAL_MODULE:= bluetoothd
LOCAL_MODULE_PATH := $(TARGET_OUT_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
LOCAL_MULTILIB := 32
include $(BUILD_EXECUTABLE)
