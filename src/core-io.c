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
#include <string.h>
#include "bt-proto.h"
#include "bt-pdubuf.h"
#include "core.h"
#include "core-io.h"

static void (*send_pdu)(struct pdu_wbuf* wbuf);

enum {
  OPCODE_REGISTER_MODULE = 0x01,
  OPCODE_UNREGISTER_MODULE = 0x02,
  OPCODE_CONFIGURE = 0x03
};

static bt_status_t
register_module(const struct pdu* cmd)
{
  uint8_t service;
  uint8_t mode;
  struct pdu_wbuf* wbuf;

  if (read_pdu_at(cmd, 0, "CC", &service, &mode) < 0)
    return BT_STATUS_FAIL;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_FAIL;

  if (core_register_module(service, mode) < 0)
    goto err_core_register_module;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_core_register_module:
  cleanup_pdu_wbuf(wbuf);
  return BT_STATUS_FAIL;
}

static bt_status_t
unregister_module(const struct pdu* cmd)
{
  uint8_t service;
  struct pdu_wbuf* wbuf;

  if (read_pdu_at(cmd, 0, "C", &service) < 0)
    return BT_STATUS_FAIL;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_FAIL;

  if (core_unregister_module(service) < 0)
    goto err_core_unregister_module;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_core_unregister_module:
  cleanup_pdu_wbuf(wbuf);
  return BT_STATUS_FAIL;
}

static bt_status_t
configure(const struct pdu* cmd)
{
  struct pdu_wbuf* wbuf;

  /* We don't support any configuration options, so there's
   * no point in unpacking the PDU. */

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_FAIL;

  if (core_configure(0, NULL) < 0)
    goto err_core_configure;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_core_configure:
  cleanup_pdu_wbuf(wbuf);
  return BT_STATUS_FAIL;
}

static bt_status_t
core_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
    [OPCODE_REGISTER_MODULE] = register_module,
    [OPCODE_UNREGISTER_MODULE] = unregister_module,
    [OPCODE_CONFIGURE] = configure
  };

  return handle_pdu_by_opcode(cmd, handler);
}

int
init_core_io(void (*send_pdu_cb)(struct pdu_wbuf*))
{
  assert(send_pdu_cb);

  if (init_core(core_handler, send_pdu_cb) < 0)
    return -1;

  send_pdu = send_pdu_cb;

  return 0;
}

void
uninit_core_io()
{
  uninit_core();
  send_pdu = NULL;
}
