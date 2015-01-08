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

struct pdu;
struct pdu_wbuf;

bt_status_t
(*register_bt_core(unsigned char mode, unsigned long max_num_clients,
                   void (*send_ntf_cb)(struct pdu_wbuf*)))(const struct pdu*);

int
unregister_bt_core(void);
