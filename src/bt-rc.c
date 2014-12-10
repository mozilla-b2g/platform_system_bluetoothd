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

#if ANDROID_VERSION >= 18

#include <assert.h>
#include "bt-core.h"
#include "bt-rc.h"
#include "log.h"

static const btrc_interface_t* btrc_interface;

int
init_bt_rc(btrc_callbacks_t* callbacks)
{
  bt_status_t status;

  if (btrc_interface) {
    ALOGE("AVRCP interface already set up");
    return -1;
  }

  btrc_interface = bt_core_get_profile_interface(BT_PROFILE_AV_RC_ID);
  if (!btrc_interface) {
    ALOGE("bt_core_get_profile_interface(BT_PROFILE_AV_RC_ID) failed");
    return -1;
  }

  assert(btrc_interface->init);
  status = btrc_interface->init(callbacks);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("btrc_interface_t::init failed");
    return -1;
  }

  return 0;
}

void
uninit_bt_rc()
{
  assert(btrc_interface);
  assert(btrc_interface->cleanup);

  btrc_interface->cleanup();
  btrc_interface = NULL;
}

/*
 * Bluedroid wrapper functions
 */

bt_status_t
bt_rc_get_play_status_rsp(btrc_play_status_t play_status, uint32_t song_len,
                          uint32_t song_pos)
{
  assert(btrc_interface);
  assert(btrc_interface->get_play_status_rsp);

  return btrc_interface->get_play_status_rsp(play_status, song_len, song_pos);
}

bt_status_t
bt_rc_list_player_app_attr_rsp(int num_attr, btrc_player_attr_t* p_attrs)
{
  assert(btrc_interface);
  assert(btrc_interface->list_player_app_attr_rsp);

  return btrc_interface->list_player_app_attr_rsp(num_attr, p_attrs);
}

bt_status_t
bt_rc_list_player_app_value_rsp(int num_val, uint8_t* p_vals)
{
  assert(btrc_interface);
  assert(btrc_interface->list_player_app_value_rsp);

  return btrc_interface->list_player_app_value_rsp(num_val, p_vals);
}

bt_status_t
bt_rc_get_player_app_value_rsp(btrc_player_settings_t* p_vals)
{
  assert(btrc_interface);
  assert(btrc_interface->get_player_app_value_rsp);

  return btrc_interface->get_player_app_value_rsp(p_vals);
}

bt_status_t
bt_rc_get_player_app_attr_text_rsp(int num_attr,
                                   btrc_player_setting_text_t* p_attrs)
{
  assert(btrc_interface);
  assert(btrc_interface->get_player_app_attr_text_rsp);

  return btrc_interface->get_player_app_attr_text_rsp(num_attr, p_attrs);
}

bt_status_t
bt_rc_get_player_app_value_text_rsp(int num_val,
                                    btrc_player_setting_text_t* p_vals)
{
  assert(btrc_interface);
  assert(btrc_interface->get_player_app_value_text_rsp);

  return btrc_interface->get_player_app_value_text_rsp(num_val, p_vals);
}

bt_status_t
bt_rc_get_element_attr_rsp(uint8_t num_attr, btrc_element_attr_val_t* p_attrs)
{
  assert(btrc_interface);
  assert(btrc_interface->get_element_attr_rsp);

  return btrc_interface->get_element_attr_rsp(num_attr, p_attrs);
}

bt_status_t
bt_rc_set_player_app_value_rsp(btrc_status_t rsp_status)
{
  assert(btrc_interface);
  assert(btrc_interface->set_player_app_value_rsp);

  return btrc_interface->set_player_app_value_rsp(rsp_status);
}

bt_status_t
bt_rc_register_notification_rsp(btrc_event_id_t event_id,
                                btrc_notification_type_t type,
                                btrc_register_notification_t* p_param)
{
  assert(btrc_interface);
  assert(btrc_interface->register_notification_rsp);

  return btrc_interface->register_notification_rsp(event_id, type, p_param);
}

#if ANDROID_VERSION >= 19
bt_status_t
bt_rc_set_volume(uint8_t volume)
{
  assert(btrc_interface);
  assert(btrc_interface->set_volume);

  return btrc_interface->set_volume(volume);
}
#endif

#endif
