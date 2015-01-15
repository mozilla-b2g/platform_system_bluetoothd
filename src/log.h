/*
 * Copyright (C) 2014  Mozilla Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#define LOG_TAG "bluetoothd"

#include <errno.h>
#include <string.h>
#include <utils/Log.h>

#define _ERRNO_STR(_func, _err) \
  "%s failed: %s", (_func), strerror(_err)

#define ALOGE_ERRNO_NO(_func, _err) \
  ALOGE(_ERRNO_STR(_func, _err))

#define ALOGE_ERRNO(_func) \
  ALOGE_ERRNO_NO(_func, errno)

#define ALOGW_ERRNO_NO(_func, _err) \
  ALOGW(_ERRNO_STR(_func, _err))

#define ALOGW_ERRNO(_func) \
  ALOGW_ERRNO_NO(_func, errno)
