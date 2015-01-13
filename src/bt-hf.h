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

#include <hardware/bluetooth.h>
#include <hardware/bt_hf.h>

int
init_bt_hf(bthf_callbacks_t* callbacks, int max_num_clients);

void
uninit_bt_hf(void);

/*
 * Bluedroid wrapper functions
 */

bt_status_t
bt_hf_connect(bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_disconnect(bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_connect_audio(bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_disconnect_audio(bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_start_voice_recognition(bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_stop_voice_recognition(bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_volume_control(bthf_volume_type_t type, int volume, bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_device_status_notification(bthf_network_state_t ntk_state,
                                 bthf_service_type_t svc_type, int signal,
                                 int batt_chg);

bt_status_t
bt_hf_cops_response(const char* cops, bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_cind_response(int svc, int num_active, int num_held,
                    bthf_call_state_t call_setup_state,
                    int signal, int roam, int batt_chg, bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_formatted_at_response(const char* rsp, bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_at_response(bthf_at_response_t response_code, int error_code,
                  bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_clcc_response(int index, bthf_call_direction_t dir,
                    bthf_call_state_t state, bthf_call_mode_t mode,
                    bthf_call_mpty_type_t mpty, const char* number,
                    bthf_call_addrtype_t type, bt_bdaddr_t* bd_addr);

bt_status_t
bt_hf_phone_state_change(int num_active, int num_held,
                         bthf_call_state_t call_setup_state,
                         const char* number, bthf_call_addrtype_t type);

#if ANDROID_VERSION >= 21
bt_status_t
bt_hf_configure_wbs(bt_bdaddr_t* bd_addr, bthf_wbs_config_t config);
#endif
