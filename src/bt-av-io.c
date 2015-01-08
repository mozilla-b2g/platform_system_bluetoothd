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
#include <fdio/task.h>
#include "bt-av.h"
#include "bt-av-io.h"
#include "bt-pdubuf.h"
#include "bt-proto.h"
#include "compiler.h"
#include "log.h"

enum {
  /* commands/responses */
  OPCODE_CONNECT = 0x01,
  OPCODE_DISCONNECT = 0x02,
  /* notifications */
  OPCODE_CONNECTION_STATE_NTF = 0x81,
  OPCODE_AUDIO_STATE_NTF = 0x82,
};

static void (*send_pdu)(struct pdu_wbuf* wbuf);

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
 * Notifications
 */

static void
connection_state_cb(btav_connection_state_t state, bt_bdaddr_t* bd_addr)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* connection state */
                         6, /* address */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_AV, OPCODE_CONNECTION_STATE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
audio_state_cb(btav_audio_state_t state, bt_bdaddr_t* bd_addr)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* audio state */
                         6, /* address */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_AV, OPCODE_AUDIO_STATE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

#if ANDROID_VERSION >= 21
static void
audio_config_cb(bt_bdaddr_t* bd_addr ATTRIBS(UNUSED),
                uint32_t sample_rate ATTRIBS(UNUSED),
                uint8_t channel_count ATTRIBS(UNUSED))
{
  /* TODO: Support HFP 1.6 HF role */
}
#endif

/*
 * Commands/Responses
 */

static bt_status_t
opcode_connect(const struct pdu* cmd)
{
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_av_connect(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_av_connect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_av_connect:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_disconnect(const struct pdu* cmd)
{
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_av_disconnect(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_av_connect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_av_connect:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
bt_av_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
    [OPCODE_CONNECT] = opcode_connect,
    [OPCODE_DISCONNECT] = opcode_disconnect,
  };

  return handle_pdu_by_opcode(cmd, handler);
}

bt_status_t
(*register_bt_av(unsigned char mode ATTRIBS(UNUSED),
                 unsigned long max_num_clients ATTRIBS(UNUSED),
                 void (*send_pdu_cb)(struct pdu_wbuf*)))(const struct pdu*)
{
  static btav_callbacks_t btav_callbacks = {
    .size = sizeof(btav_callbacks),
    .connection_state_cb = connection_state_cb,
    .audio_state_cb = audio_state_cb,
#if ANDROID_VERSION >= 21
    .audio_config_cb = audio_config_cb
#endif
  };

  if (init_bt_av(&btav_callbacks) < 0)
    return NULL;

  send_pdu = send_pdu_cb;

  return bt_av_handler;
}

int
unregister_bt_av()
{
  uninit_bt_av();
  return 0;
}
