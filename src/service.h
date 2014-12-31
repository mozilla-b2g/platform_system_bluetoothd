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

typedef bt_status_t (*register_func)(const struct pdu*);

extern bt_status_t (*service_handler[256])(const struct pdu*);

extern register_func
  (* const register_service[256])(unsigned char, unsigned long,
                                  void (*)(struct pdu_wbuf*));

extern int (*unregister_service[256])(void);
