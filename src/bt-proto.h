/*
 * Copyright (C) 2014-2015  Mozilla Foundation
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

#include <stdint.h>
#include <hardware/bluetooth.h>

enum {
  SERVICE_CORE = 0x00,
  SERVICE_BT_CORE = 0x01,
  SERVICE_BT_SOCK = 0x02,
  SERVICE_BT_HF = 0x05,
  SERVICE_BT_AV = 0x06,
  SERVICE_BT_RC = 0x08,
  SERVICE_BT_GATT = 0x09
};

struct pdu {
  uint8_t service;
  uint8_t opcode;
  uint16_t len;
  unsigned char data[];
} __attribute__((packed));

void
init_pdu(struct pdu* pdu, uint8_t service, uint8_t opcode);

size_t
pdu_size(const struct pdu* pdu);

bt_status_t
handle_pdu_by_service(const struct pdu* cmd,
                      bt_status_t (* const handler[256])(const struct pdu*));

bt_status_t
handle_pdu_by_opcode(const struct pdu* cmd,
                     bt_status_t (* const handler[256])(const struct pdu*));

long
read_pdu_at(const struct pdu* pdu, unsigned long offset, const char* fmt,
            ...);

long
read_bt_property_t(const struct pdu* pdu, unsigned long offset,
                   bt_property_t* property);

long
read_bt_bdaddr_t(const struct pdu* pdu, unsigned long offset,
                 bt_bdaddr_t* addr);

long
read_bt_uuid_t(const struct pdu* pdu, unsigned long offset, bt_uuid_t* uuid);

long
read_bt_pin_code_t(const struct pdu* pdu, unsigned long off,
                   bt_pin_code_t* pin_code);

long
write_pdu_at(struct pdu* pdu, unsigned long offset, const char* fmt, ...);

long
append_bt_property_t(struct pdu* pdu, const bt_property_t* property);

long
append_to_pdu(struct pdu* pdu, const char* fmt, ...);

long
append_bt_property_t(struct pdu* pdu, const bt_property_t* property);

long
append_bt_property_t_array(struct pdu* pdu,
                           const bt_property_t* properties,
                           unsigned long num_properties);

long
append_bt_bdaddr_t(struct pdu* pdu, const bt_bdaddr_t* addr);

long
append_bt_bdname_t(struct pdu* pdu, const bt_bdname_t* name);

long
append_bt_uuid_t(struct pdu* pdu, const bt_uuid_t* uuid);
