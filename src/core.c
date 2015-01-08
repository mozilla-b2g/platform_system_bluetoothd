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
#include "compiler.h"
#include "log.h"
#include "service.h"
#include "bt-proto.h"
#include "core.h"

struct pdu_wbuf;

static void (*send_pdu)(struct pdu_wbuf*);

int
core_register_module(unsigned char service, unsigned char mode,
                     unsigned long max_num_clients)
{
  bt_status_t (*handler)(const struct pdu*);

  if (service_handler[service]) {
    ALOGE("service 0x%x already registered", service);
    return -1;
  }
  if (!register_service[service]) {
    ALOGE("invalid service id 0x%x", service);
    return -1;
  }
  handler = register_service[service](mode, max_num_clients, send_pdu);
  if (!handler)
    return -1;

  service_handler[service] = handler;

  return 0;
}

int
core_unregister_module(unsigned char service)
{
  if (service == SERVICE_CORE) {
    ALOGE("service CORE cannot be unregistered");
    return -1;
  }
  if (!unregister_service[service]) {
    ALOGE("service 0x%x not registered", service);
    return -1;
  }
  if (unregister_service[service]() < 0)
    return -1;

  service_handler[service] = NULL;

  return 0;
}

int
core_configure(unsigned char num_options ATTRIBS(UNUSED),
               const void* options ATTRIBS(UNUSED))
{
  return 0;
}

int
init_core(bt_status_t (*core_handler)(const struct pdu*),
          void (*send_pdu_cb)(struct pdu_wbuf*))
{
  assert(core_handler);

  service_handler[SERVICE_CORE] = core_handler;
  send_pdu = send_pdu_cb;

  return 0;
}

void
uninit_core()
{
  send_pdu = NULL;
  service_handler[SERVICE_CORE] = NULL;
}
