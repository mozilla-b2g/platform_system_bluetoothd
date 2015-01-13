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

#if ANDROID_VERSION >= 21
int
init_bt_core(bt_callbacks_t* callbacks, bt_os_callouts_t* callouts);
#else
int
init_bt_core(bt_callbacks_t* callbacks);
#endif

void
uninit_bt_core(void);

/*
 * Bluedroid wrapper functions
 */

int
bt_core_enable(void);

int
bt_core_disable(void);

void
bt_core_cleanup(void);

int
bt_core_get_adapter_properties(void);

int
bt_core_get_adapter_property(bt_property_type_t type);

int
bt_core_set_adapter_property(const bt_property_t* property);

int
bt_core_get_remote_device_properties(bt_bdaddr_t* remote_addr);

int
bt_core_get_remote_device_property(bt_bdaddr_t *remote_addr,
                              bt_property_type_t type);

int
bt_core_set_remote_device_property(bt_bdaddr_t* remote_addr,
                        const bt_property_t *property);

int
bt_core_get_remote_service_record(bt_bdaddr_t* remote_addr, bt_uuid_t* uuid);

int
bt_core_get_remote_services(bt_bdaddr_t* remote_addr);

int
bt_core_start_discovery(void);

int
bt_core_cancel_discovery(void);

int
bt_core_create_bond(const bt_bdaddr_t* bd_addr, int transport);

int
bt_core_remove_bond(const bt_bdaddr_t* bd_addr);

int
bt_core_cancel_bond(const bt_bdaddr_t* bd_addr);

int
bt_core_pin_reply(const bt_bdaddr_t* bd_addr, uint8_t accept, uint8_t pin_len,
             bt_pin_code_t* pin_code);

int
bt_core_ssp_reply(const bt_bdaddr_t* bd_addr, bt_ssp_variant_t variant,
             uint8_t accept, uint32_t passkey);

const void*
bt_core_get_profile_interface(const char* profile_id);

int
bt_core_dut_mode_configure(uint8_t enable);

int
bt_core_dut_mode_send(uint16_t opcode, uint8_t* buf, uint8_t len);

int
bt_core_le_test_mode(uint16_t opcode, uint8_t* buf, uint8_t len);

int
bt_core_config_hci_snoop_log(uint8_t enable);
