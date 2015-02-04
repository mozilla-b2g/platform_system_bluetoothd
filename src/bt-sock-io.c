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

#include <assert.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_sock.h>
#include <string.h>
#include <sys/socket.h>
#include "compiler.h"
#include "log.h"
#include "bt-proto.h"
#include "bt-pdubuf.h"
#include "bt-core-io.h"
#include "bt-sock-io.h"

enum {
  OPCODE_LISTEN = 0x01,
  OPCODE_CONNECT = 0x02
};

/* We need a few bytes at the beginning of the PDU's
 * tail buffer to align our data structure correctly.
 */
static const unsigned long ALIGNMENT_PADDING = sizeof(void*);

static void (*send_pdu)(struct pdu_wbuf* wbuf);
static const btsock_interface_t* btsock_interface;

static uintptr_t
_ceil_align(uintptr_t ptr, uintptr_t align)
{
  return ((ptr / align) + 1) * align;
}

static void*
ceil_align(void* ptr, size_t align)
{
  return (void*)_ceil_align((uintptr_t)ptr, (uintptr_t)align);
}

struct ancillary_data {
  int sock_fd;
  unsigned char cmsgbuf[CMSG_SPACE(sizeof(int))];
};

static int
build_ancillary_data(struct pdu_wbuf* wbuf, struct msghdr* msg)
{
  struct ancillary_data* data;
  struct cmsghdr* chdr;

  assert(msg);

  data = ceil_align(pdu_wbuf_tail(wbuf), ALIGNMENT_PADDING);

  msg->msg_control = data->cmsgbuf;
  msg->msg_controllen = sizeof(data->cmsgbuf);

  chdr = CMSG_FIRSTHDR(msg);
  chdr->cmsg_len = CMSG_LEN(sizeof(data->sock_fd));
  chdr->cmsg_level = SOL_SOCKET;
  chdr->cmsg_type = SCM_RIGHTS;
  memcpy(CMSG_DATA(chdr), &data->sock_fd, sizeof(data->sock_fd));

  msg->msg_controllen = chdr->cmsg_len;

  return 0;
}

/*
 * Commands/Responses
 */

static bt_status_t
opcode_listen(const struct pdu* cmd)
{
  uint8_t type;
  int8_t service_name[256];
  uint8_t uuid[16];
  uint32_t channel;
  uint8_t flags;
  struct pdu_wbuf* wbuf;
  struct ancillary_data* data;
  bt_status_t status;

  assert(btsock_interface);
  assert(btsock_interface->listen);

  if (read_pdu_at(cmd, 0, "CmmIC", &type,
                                   service_name, (size_t)sizeof(service_name),
                                   uuid, (size_t)sizeof(uuid),
                                   &channel, &flags) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0,
                         ALIGNMENT_PADDING + sizeof(*data),
                         build_ancillary_data);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  data = ceil_align(pdu_wbuf_tail(wbuf), ALIGNMENT_PADDING);

  status = btsock_interface->listen(type, (char*)service_name, uuid, channel,
                                    &data->sock_fd, flags);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_sock_listen;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_sock_listen:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_connect(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  uint8_t type;
  uint8_t uuid[16];
  int32_t channel;
  uint8_t flags;
  struct pdu_wbuf* wbuf;
  struct ancillary_data* data;
  bt_status_t status;

  assert(btsock_interface);
  assert(btsock_interface->connect);

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;
  if (read_pdu_at(cmd, off, "CmiC", &type, uuid, sizeof(uuid),
                                    &channel, &flags) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0,
                         ALIGNMENT_PADDING + sizeof(*data),
                         build_ancillary_data);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  data = ceil_align(pdu_wbuf_tail(wbuf), ALIGNMENT_PADDING);

  status = btsock_interface->connect(&bd_addr, type, uuid, channel,
                                     &data->sock_fd, flags);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_sock_connect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_sock_connect:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
bt_sock_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
    [OPCODE_LISTEN] = opcode_listen,
    [OPCODE_CONNECT] = opcode_connect,
  };

  return handle_pdu_by_opcode(cmd, handler);
}

bt_status_t
(*register_bt_sock(unsigned char mode ATTRIBS(UNUSED),
                   unsigned long max_num_clients ATTRIBS(UNUSED),
                   void (*send_pdu_cb)(struct pdu_wbuf*)))(const struct pdu*)
{
  if (btsock_interface) {
    ALOGE("Socket interface already set up");
    return NULL;
  }

  btsock_interface = get_profile_interface(BT_PROFILE_SOCKETS_ID);
  if (!btsock_interface) {
    ALOGE("get_profile_interface(BT_PROFILE_SOCKETS_ID) failed");
    return NULL;
  }

  send_pdu = send_pdu_cb;

  return bt_sock_handler;
}

int
unregister_bt_sock()
{
  assert(btsock_interface);

  btsock_interface = NULL;

  return 0;
}
