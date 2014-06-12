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

#include <stdint.h>
#include <hardware/bluetooth.h>

enum {
  SERVICE_CORE = 0x00
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
write_pdu_at(struct pdu* pdu, unsigned long offset, const char* fmt, ...);

long
append_to_pdu(struct pdu* pdu, const char* fmt, ...);
