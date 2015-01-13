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

struct pdu;
struct pdu_wbuf;

int
core_register_module(unsigned char service, unsigned char mode,
                     unsigned long max_num_clients);

int
core_unregister_module(unsigned char service);

int
core_configure(unsigned char num_options, const void* options);

int
init_core(bt_status_t (*core_handler)(const struct pdu*),
          void (*send_pdu_cb)(struct pdu_wbuf*));

void
uninit_core(void);
