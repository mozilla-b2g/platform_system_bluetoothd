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
#include "bt-core.h"
#include "bt-hf.h"
#include "log.h"
#include "compiler.h"

static const bthf_interface_t* bthf_interface;

int
init_bt_hf(bthf_callbacks_t* callbacks, int max_num_clients ATTRIBS(UNUSED))
{
  bt_status_t status;

  if (bthf_interface) {
    ALOGE("Handsfree interface already set up");
    return -1;
  }

  bthf_interface = bt_core_get_profile_interface(BT_PROFILE_HANDSFREE_ID);
  if (!bthf_interface) {
    ALOGE("bt_core_get_profile_interface(BT_PROFILE_HANDSFREE_ID) failed");
    return -1;
  }

  assert(bthf_interface->init);
#if ANDROID_VERSION >= 21
  status = bthf_interface->init(callbacks, max_num_clients);
#else
  status = bthf_interface->init(callbacks);
#endif
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("bthf_interface_t::init failed");
    return -1;
  }

  return 0;
}

void
uninit_bt_hf()
{
  assert(bthf_interface);
  assert(bthf_interface->cleanup);

  bthf_interface->cleanup();
  bthf_interface = NULL;
}

/*
 * Bluedroid wrapper functions
 */

bt_status_t
bt_hf_connect(bt_bdaddr_t* bd_addr)
{
  assert(bthf_interface);
  assert(bthf_interface->connect);

  return bthf_interface->connect(bd_addr);
}

bt_status_t
bt_hf_disconnect(bt_bdaddr_t* bd_addr)
{
  assert(bthf_interface);
  assert(bthf_interface->disconnect);

  return bthf_interface->disconnect(bd_addr);
}

bt_status_t
bt_hf_connect_audio(bt_bdaddr_t* bd_addr)
{
  assert(bthf_interface);
  assert(bthf_interface->connect_audio);

  return bthf_interface->connect_audio(bd_addr);
}

bt_status_t
bt_hf_disconnect_audio(bt_bdaddr_t* bd_addr)
{
  assert(bthf_interface);
  assert(bthf_interface->disconnect_audio);

  return bthf_interface->disconnect_audio(bd_addr);
}

bt_status_t
bt_hf_start_voice_recognition(bt_bdaddr_t* bd_addr ATTRIBS(UNUSED))
{
  assert(bthf_interface);
  assert(bthf_interface->start_voice_recognition);

#if ANDROID_VERSION >= 21
  return bthf_interface->start_voice_recognition(bd_addr);
#else
  return bthf_interface->start_voice_recognition();
#endif
}

bt_status_t
bt_hf_stop_voice_recognition(bt_bdaddr_t* bd_addr ATTRIBS(UNUSED))
{
  assert(bthf_interface);
  assert(bthf_interface->stop_voice_recognition);

#if ANDROID_VERSION >= 21
  return bthf_interface->stop_voice_recognition(bd_addr);
#else
  return bthf_interface->stop_voice_recognition();
#endif
}

bt_status_t
bt_hf_volume_control(bthf_volume_type_t type, int volume,
                     bt_bdaddr_t* bd_addr ATTRIBS(UNUSED))
{
  assert(bthf_interface);
  assert(bthf_interface->volume_control);

#if ANDROID_VERSION >= 21
  return bthf_interface->volume_control(type, volume, bd_addr);
#else
  return bthf_interface->volume_control(type, volume);
#endif
}

bt_status_t
bt_hf_device_status_notification(bthf_network_state_t ntk_state,
                                 bthf_service_type_t svc_type, int signal,
                                 int batt_chg)
{
  assert(bthf_interface);
  assert(bthf_interface->device_status_notification);

  return bthf_interface->device_status_notification(ntk_state, svc_type,
                                                    signal, batt_chg);
}

bt_status_t
bt_hf_cops_response(const char* cops, bt_bdaddr_t* bd_addr ATTRIBS(UNUSED))
{
  assert(bthf_interface);
  assert(bthf_interface->cops_response);

#if ANDROID_VERSION >= 21
  return bthf_interface->cops_response(cops, bd_addr);
#else
  return bthf_interface->cops_response(cops);
#endif
}

bt_status_t
bt_hf_cind_response(int svc, int num_active, int num_held,
                    bthf_call_state_t call_setup_state,
                    int signal, int roam, int batt_chg,
                    bt_bdaddr_t* bd_addr ATTRIBS(UNUSED))
{
  assert(bthf_interface);
  assert(bthf_interface->cind_response);

#if ANDROID_VERSION >= 21
  return bthf_interface->cind_response(svc, num_active, num_held,
                                       call_setup_state, signal, roam,
                                       batt_chg, bd_addr);
#else
  return bthf_interface->cind_response(svc, num_active, num_held,
                                       call_setup_state, signal, roam,
                                       batt_chg);
#endif
}

bt_status_t
bt_hf_formatted_at_response(const char* rsp,
                            bt_bdaddr_t* bd_addr ATTRIBS(UNUSED))
{
  assert(bthf_interface);
  assert(bthf_interface->formatted_at_response);

#if ANDROID_VERSION >= 21
  return bthf_interface->formatted_at_response(rsp, bd_addr);
#else
  return bthf_interface->formatted_at_response(rsp);
#endif
}

bt_status_t
bt_hf_at_response(bthf_at_response_t response_code, int error_code,
                  bt_bdaddr_t* bd_addr ATTRIBS(UNUSED))
{
  assert(bthf_interface);
  assert(bthf_interface->at_response);

#if ANDROID_VERSION >= 21
  return bthf_interface->at_response(response_code, error_code, bd_addr);
#else
  return bthf_interface->at_response(response_code, error_code);
#endif
}

bt_status_t
bt_hf_clcc_response(int index, bthf_call_direction_t dir,
                    bthf_call_state_t state, bthf_call_mode_t mode,
                    bthf_call_mpty_type_t mpty, const char* number,
                    bthf_call_addrtype_t type,
                    bt_bdaddr_t* bd_addr ATTRIBS(UNUSED))
{
  assert(bthf_interface);
  assert(bthf_interface->clcc_response);

#if ANDROID_VERSION >= 21
  return bthf_interface->clcc_response(index, dir, state, mode, mpty, number,
                                       type, bd_addr);
#else
  return bthf_interface->clcc_response(index, dir, state, mode, mpty, number,
                                       type);
#endif
}

bt_status_t
bt_hf_phone_state_change(int num_active, int num_held,
                         bthf_call_state_t call_setup_state,
                         const char* number, bthf_call_addrtype_t type)
{
  assert(bthf_interface);
  assert(bthf_interface->phone_state_change);

  return bthf_interface->phone_state_change(num_active, num_held,
                                            call_setup_state, number, type);
}
