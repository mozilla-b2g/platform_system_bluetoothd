/*
 * Copyright (C) 2015  Mozilla Foundation
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
#include <fdio/task.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_pan.h>
#include <stdlib.h>
#include "compiler.h"
#include "log.h"
#include "bt-proto.h"
#include "bt-pdubuf.h"
#include "bt-core-io.h"
#include "bt-pan-io.h"

#define IFNAME_LEN 17 /* interface name */

enum {
  /* commands/responses */
  OPCODE_ENABLE = 0x01,
  OPCODE_GET_LOCAL_ROLE = 0x02,
  OPCODE_CONNECT = 0x03,
  OPCODE_DISCONNECT = 0x04,
  /* notifications */
  OPCODE_CONTROL_STATE_NTF = 0x81,
  OPCODE_CONNECTION_STATE_NTF = 0x82,
};

static void (*send_pdu)(struct pdu_wbuf* wbuf);
static const btpan_interface_t* btpan_interface;

static enum ioresult
send_ntf_pdu(void* data)
{
  /* send notification on I/O thread */
  if (!send_pdu) {
    ALOGE("send_pdu is NULL");
    return IO_OK;
  }
  send_pdu(data);
  return IO_OK;
}

/*
 * Protocol helper
 */

static long
append_bt_ifname(struct pdu* pdu, const char* ifname)
{
  static const uint8_t padding[IFNAME_LEN];
  size_t len, padding_len;

  len = strnlen(ifname, IFNAME_LEN) + 1; /* '\0'-terminated */

  /* Error handling */
  if (len > IFNAME_LEN) {
    ALOGE("interface name exceed %d bytes",IFNAME_LEN);
    return append_to_pdu(pdu, "m", ifname, (size_t)IFNAME_LEN);
  }
  padding_len = IFNAME_LEN - len;

  return append_to_pdu(pdu, "mm", ifname, (size_t)len, padding, (size_t)padding_len);
}

/*
 * Notifications
 */

static void
control_state_cb(btpan_control_state_t state, bt_status_t error,
                 int local_role, const char* ifname)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* control state */
                         1 + /* status */
                         1 + /* local role */
                         IFNAME_LEN, /* interface name */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_PAN, OPCODE_CONTROL_STATE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)error) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)local_role) < 0) ||
      (append_bt_ifname(&wbuf->buf.pdu, ifname) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
connection_state_cb(btpan_connection_state_t state, bt_status_t error,
                    const bt_bdaddr_t *bd_addr, int local_role, int remote_role)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* connection state */
                         1 + /* status */
                         6 + /* address */
                         1 + /* local role */
                         1, /* remote role */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_PAN, OPCODE_CONNECTION_STATE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)error) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)local_role) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)remote_role) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

/*
 * Commands/Responses
 */

static bt_status_t
opcode_enable(const struct pdu* cmd)
{
  long off;
  uint8_t local_role;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btpan_interface);
  assert(btpan_interface->enable);

  off = read_pdu_at(cmd, 0, "C", &local_role);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = btpan_interface->enable(local_role);
  if (status != BT_STATUS_SUCCESS)
    goto err_btpan_interface_enable;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btpan_interface_enable:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_get_local_role(const struct pdu* cmd)
{
  struct pdu_wbuf* wbuf;
  uint8_t local_role;
  bt_status_t status;

  assert(btpan_interface);
  assert(btpan_interface->get_local_role);

  wbuf = create_pdu_wbuf(1, /* local role */
                         0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  local_role = btpan_interface->get_local_role();

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)local_role) < 0) {
    status = BT_STATUS_FAIL;
    goto cleanup;
  }

  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
cleanup:
  cleanup_pdu_wbuf(wbuf);
  return status;
}


static bt_status_t
opcode_connect(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;
  uint8_t local_role, remote_role;

  assert(btpan_interface);
  assert(btpan_interface->connect);

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0){
    status = BT_STATUS_PARM_INVALID;
    goto err_read_bt_bdaddr_t;
  }

  if (read_pdu_at(cmd, off, "CC", &local_role, &remote_role) < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = btpan_interface->connect(&bd_addr, local_role, remote_role);
  if (status != BT_STATUS_SUCCESS)
    goto err_btpan_interface_connect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btpan_interface_connect:
  cleanup_pdu_wbuf(wbuf);
err_read_bt_bdaddr_t:
err_read_pdu_at:
  return status;
}

static bt_status_t
opcode_disconnect(const struct pdu* cmd)
{
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btpan_interface);
  assert(btpan_interface->disconnect);

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = btpan_interface->disconnect(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_btpan_interface_disconnect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btpan_interface_disconnect:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
bt_pan_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
    [OPCODE_ENABLE] = opcode_enable,
    [OPCODE_GET_LOCAL_ROLE] = opcode_get_local_role,
    [OPCODE_CONNECT] = opcode_connect,
    [OPCODE_DISCONNECT] = opcode_disconnect
  };

  return handle_pdu_by_opcode(cmd, handler);
}

bt_status_t
(*register_bt_pan(unsigned char mode ATTRIBS(UNUSED),
                 unsigned long max_num_clients ATTRIBS(UNUSED),
                 void (*send_pdu_cb)(struct pdu_wbuf*)))(const struct pdu*)
{
  static btpan_callbacks_t btpan_callbacks = {
    .size = sizeof(btpan_callbacks),
    .control_state_cb = control_state_cb,
    .connection_state_cb = connection_state_cb
  };

  bt_status_t status;

  if (btpan_interface) {
    ALOGE("PAN interface already set up");
    return NULL;
  }

  btpan_interface = get_profile_interface(BT_PROFILE_PAN_ID);
  if (!btpan_interface) {
    ALOGE("get_profile_interface(BT_PROFILE_PAN_ID) failed");
    return NULL;
  }

  assert(btpan_interface->init);

  status = btpan_interface->init(&btpan_callbacks);

  if (status != BT_STATUS_SUCCESS) {
    ALOGE("btpan_interface_t::init failed");
    return NULL;
  }

  send_pdu = send_pdu_cb;

  return bt_pan_handler;
}

int
unregister_bt_pan()
{
  assert(btpan_interface);
  assert(btpan_interface->cleanup);

  btpan_interface->cleanup();
  btpan_interface = NULL;

  return 0;
}
