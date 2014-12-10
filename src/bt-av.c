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

#include <assert.h>
#include "bt-av.h"
#include "bt-core.h"
#include "log.h"

static const btav_interface_t* btav_interface;

int
init_bt_av(btav_callbacks_t* callbacks)
{
  bt_status_t status;

  if (btav_interface) {
    ALOGE("A2DP interface already set up");
    return -1;
  }

  btav_interface = bt_core_get_profile_interface(BT_PROFILE_ADVANCED_AUDIO_ID);
  if (!btav_interface) {
    ALOGE("bt_core_get_profile_interface(BT_PROFILE_ADVANCED_AUDIO_ID) failed");
    return -1;
  }

  assert(btav_interface->init);
  status = btav_interface->init(callbacks);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("btav_interface_t::init failed");
    return -1;
  }

  return 0;
}

void
uninit_bt_av()
{
  assert(btav_interface);
  assert(btav_interface->cleanup);

  btav_interface->cleanup();
  btav_interface = NULL;
}

/*
 * Bluedroid wrapper functions
 */

bt_status_t
bt_av_connect(bt_bdaddr_t* bd_addr)
{
  assert(btav_interface);
  assert(btav_interface->connect);
  assert(bd_addr);

  return btav_interface->connect(bd_addr);
}

bt_status_t
bt_av_disconnect(bt_bdaddr_t* bd_addr)
{
  assert(btav_interface);
  assert(btav_interface->disconnect);
  assert(bd_addr);

  return btav_interface->disconnect(bd_addr);
}
