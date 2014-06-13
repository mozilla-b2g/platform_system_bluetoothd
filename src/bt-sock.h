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
#include <hardware/bt_sock.h>

int
init_bt_sock(void);

void
uninit_bt_sock(void);

/*
 * Bluedroid wrapper functions
 */

bt_status_t
bt_sock_listen(btsock_type_t type,
               const char* service_name, const uint8_t* service_uuid,
               int channel, int* sock_fd, int flags);

bt_status_t
bt_sock_connect(const bt_bdaddr_t* bd_addr, btsock_type_t type,
                const uint8_t* uuid, int channel, int* sock_fd, int flags);
