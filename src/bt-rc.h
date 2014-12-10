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

#if ANDROID_VERSION >= 18

#include <hardware/bluetooth.h>
#include <hardware/bt_rc.h>

int
init_bt_rc(btrc_callbacks_t* callbacks);

void
uninit_bt_rc(void);

/*
 * Bluedroid wrapper functions
 */

bt_status_t
bt_rc_get_play_status_rsp(btrc_play_status_t play_status, uint32_t song_len,
                          uint32_t song_pos);

bt_status_t
bt_rc_list_player_app_attr_rsp(int num_attr, btrc_player_attr_t* p_attrs);

bt_status_t
bt_rc_list_player_app_value_rsp(int num_val, uint8_t* p_vals);

bt_status_t
bt_rc_get_player_app_value_rsp(btrc_player_settings_t* p_vals);

bt_status_t
bt_rc_get_player_app_attr_text_rsp(int num_attr,
                                   btrc_player_setting_text_t* p_attrs);

bt_status_t
bt_rc_get_player_app_value_text_rsp(int num_val,
                                    btrc_player_setting_text_t* p_vals);

bt_status_t
bt_rc_get_element_attr_rsp(uint8_t num_attr, btrc_element_attr_val_t* p_attrs);

bt_status_t
bt_rc_set_player_app_value_rsp(btrc_status_t rsp_status);

bt_status_t
bt_rc_register_notification_rsp(btrc_event_id_t event_id,
                                btrc_notification_type_t type,
                                btrc_register_notification_t* p_param);

#if ANDROID_VERSION >= 19
bt_status_t
bt_rc_set_volume(uint8_t volume);
#endif

#endif
