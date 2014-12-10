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

#include "bt-proto.h"
#include "bt-core-io.h"
#include "bt-sock-io.h"
#include "bt-hf-io.h"
#include "bt-av-io.h"
#include "bt-rc-io.h"
#include "service.h"

bt_status_t (*service_handler[256])(const struct pdu*);

register_func
  (* const register_service[256])(unsigned char, void (*)(struct pdu_wbuf*)) = {
  /* SERVICE_CORE is special and not handled here */
  [SERVICE_BT_CORE] = register_bt_core,
  [SERVICE_BT_SOCK] = register_bt_sock,
  [SERVICE_BT_HF] = register_bt_hf,
  [SERVICE_BT_AV] = register_bt_av,
  [SERVICE_BT_RC] = register_bt_rc
};

int (*unregister_service[256])() = {
  [SERVICE_BT_CORE] = unregister_bt_core,
  [SERVICE_BT_SOCK] = unregister_bt_sock,
  [SERVICE_BT_HF] = unregister_bt_hf,
  [SERVICE_BT_AV] = unregister_bt_av,
  [SERVICE_BT_RC] = unregister_bt_rc
};
