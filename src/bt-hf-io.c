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
#include "bt-hf.h"
#include "bt-hf-io.h"
#include "bt-pdubuf.h"
#include "bt-proto.h"
#include "log.h"
#include "compiler.h"

enum {
  /* commands/responses */
  OPCODE_CONNECT = 0x01,
  OPCODE_DISCONNECT = 0x02,
  OPCODE_CONNECT_AUDIO = 0x03,
  OPCODE_DISCONNECT_AUDIO = 0x04,
  OPCODE_START_VOICE_RECOGNITION = 0x05,
  OPCODE_STOP_VOICE_RECOGNITION =0x06,
  OPCODE_VOLUME_CONTROL = 0x07,
  OPCODE_DEVICE_STATUS_NOTIFICATION = 0x08,
  OPCODE_COPS_RESPONSE = 0x09,
  OPCODE_CIND_RESPONSE = 0x0a,
  OPCODE_FORMATTED_AT_RESPONSE = 0x0b,
  OPCODE_AT_RESPONSE = 0x0c,
  OPCODE_CLCC_RESPONSE = 0x0d,
  OPCODE_PHONE_STATE_CHANGE = 0x0e,
  /* notifications */
  OPCODE_CONNECTION_STATE_NTF = 0x81,
  OPCODE_AUDIO_STATE_NTF = 0x82,
  OPCODE_VR_CMD_NTF = 0x83,
  OPCODE_ANSWER_CALL_CMD_NTF = 0x84,
  OPCODE_HANGUP_CALL_CMD_NTF = 0x85,
  OPCODE_VOLUME_CMD_NTF = 0x86,
  OPCODE_DIAL_CALL_CMD_NTF = 0x87,
  OPCODE_DTMF_CMD_NTF = 0x88,
  OPCODE_NREC_CMD_NTF = 0x89,
  OPCODE_CHLD_CMD_NTF = 0x8a,
  OPCODE_CNUM_CMD_NTF = 0x8b,
  OPCODE_CIND_CMD_NTF = 0x8c,
  OPCODE_COPS_CMD_NTF = 0x8d,
  OPCODE_CLCC_CMD_NTF = 0x8e,
  OPCODE_UNKNOWN_AT_CMD_NTF = 0x8f,
  OPCODE_KEY_PRESSED_CMD_NTF =0x90
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
connection_state_cb(bthf_connection_state_t state, bt_bdaddr_t* bd_addr)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* connection state */
                         6, /* address */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_CONNECTION_STATE_NTF);
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
audio_state_cb(bthf_audio_state_t state, bt_bdaddr_t* bd_addr)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* audio state */
                         6, /* address */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_AUDIO_STATE_NTF);
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
vr_cmd_cb(bthf_vr_state_t state)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1, /* voice-recognition state */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_VR_CMD_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
answer_call_cmd_cb(void)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_ANSWER_CALL_CMD_NTF);

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
hangup_call_cmd_cb(void)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_HANGUP_CALL_CMD_NTF);

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
volume_cmd_cb(bthf_volume_type_t type, int volume)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* volume type */
                         1, /* volume */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_VOLUME_CMD_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "CC", (uint8_t)type, (uint8_t)volume) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
dial_call_cmd_cb(char* number)
{
  struct pdu_wbuf* wbuf;
  size_t len;

  assert(number);

  len = strlen(number) + 1;

  wbuf = create_pdu_wbuf(len, /* phone number */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_DIAL_CALL_CMD_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "m", number, len) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
dtmf_cmd_cb(char tone)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1, /* tone */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_DTMF_CMD_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "c", (int8_t)tone) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
nrec_cmd_cb(bthf_nrec_t nrec)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1, /* NREC */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_NREC_CMD_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)nrec) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
chld_cmd_cb(bthf_chld_type_t chld)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1, /* CHLD type */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_CHLD_CMD_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)chld) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
cnum_cmd_cb(void)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_CNUM_CMD_NTF);

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
cind_cmd_cb(void)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_CIND_CMD_NTF);

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
cops_cmd_cb(void)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_COPS_CMD_NTF);

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
clcc_cmd_cb(void)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_CLCC_CMD_NTF);

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
unknown_at_cmd_cb(char* at_string)
{
  struct pdu_wbuf* wbuf;
  size_t len;

  assert(at_string);

  len = strlen(at_string) + 1;

  wbuf = create_pdu_wbuf(len, /* AT string */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_UNKNOWN_AT_CMD_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "m", at_string, len) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
key_pressed_cmd_cb(void)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HF, OPCODE_KEY_PRESSED_CMD_NTF);

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

  status = bt_hf_connect(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_connect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_connect:
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

  status = bt_hf_disconnect(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_connect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_connect:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_connect_audio(const struct pdu* cmd)
{
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_hf_connect_audio(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_connect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_connect:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_disconnect_audio(const struct pdu* cmd)
{
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_hf_disconnect_audio(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_connect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_connect:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_start_voice_recognition(const struct pdu* cmd)
{
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_hf_start_voice_recognition();
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_start_voice_recognition;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_start_voice_recognition:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_stop_voice_recognition(const struct pdu* cmd)
{
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_hf_stop_voice_recognition();
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_stop_voice_recognition;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_stop_voice_recognition:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_volume_control(const struct pdu* cmd)
{
  uint8_t type, volume;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  if (read_pdu_at(cmd, 0, "CC", &type, &volume) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_hf_volume_control(type, volume);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_volume_control;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_volume_control:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_device_status_notification(const struct pdu* cmd)
{
  uint8_t state, type, signal, level;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  if (read_pdu_at(cmd, 0, "CCCC", &state, &type, &signal, &level) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_hf_device_status_notification(state, type, signal, level);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_device_status_notification;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_device_status_notification:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_cops_response(const struct pdu* cmd)
{
  void* rsp;
  bt_status_t status;
  struct pdu_wbuf* wbuf;

  cmd = NULL;

  if (read_pdu_at(cmd, 0, "0", &rsp) < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = bt_hf_cops_response(rsp);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_cops_response;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(rsp);

  return BT_STATUS_SUCCESS;
err_bt_hf_cops_response:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
err_read_pdu_at:
  free(rsp);
  return status;
}

static bt_status_t
opcode_cind_response(const struct pdu* cmd)
{
  uint8_t service, nactive, nheld, state, signal, roaming, level;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  if (read_pdu_at(cmd, 0, "CCCCCCC", &service, &nactive, &nheld, &state,
                                     &signal, &roaming, &level) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_hf_cind_response(service, nactive, nheld, state,
                               signal, roaming, level);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_device_status_notification;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_device_status_notification:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_formatted_at_response(const struct pdu* cmd)
{
  void* rsp;
  bt_status_t status;
  struct pdu_wbuf* wbuf;

  rsp = NULL;

  if (read_pdu_at(cmd, 0, "0", &rsp) < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = bt_hf_formatted_at_response(rsp);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_formatted_at_response;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(rsp);

  return BT_STATUS_SUCCESS;
err_bt_hf_formatted_at_response:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
err_read_pdu_at:
  free(rsp);
  return status;
}

static bt_status_t
opcode_at_response(const struct pdu* cmd)
{
  uint8_t rsp, error;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  if (read_pdu_at(cmd, 0, "CC", &rsp, &error) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_hf_at_response(rsp, error);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_at_response;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_hf_at_response:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_clcc_response(const struct pdu* cmd)
{
  uint8_t index, dir, state, mode, mpty, type;
  void* number;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  number = NULL;

  if (read_pdu_at(cmd, 0, "CCCCCC0", &index, &dir, &state, &mode,
                                     &mpty, &type, &number) < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = bt_hf_clcc_response(index, dir, state, mode, mpty, number, type);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_clcc_response;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(number);

  return BT_STATUS_SUCCESS;
err_bt_hf_clcc_response:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
err_read_pdu_at:
  free(number);
  return status;
}

static bt_status_t
opcode_phone_state_change(const struct pdu* cmd)
{
  uint8_t num_active, num_held, call_setup_state, type;
  void* number;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  number = NULL;

  if (read_pdu_at(cmd, 0, "CCCC0", &num_active, &num_held, &call_setup_state,
                                   &type, &number) < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = bt_hf_phone_state_change(num_active, num_held, call_setup_state,
                                    number, type);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_hf_phone_state_change;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(number);

  return BT_STATUS_SUCCESS;
err_bt_hf_phone_state_change:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
err_read_pdu_at:
  free(number);
  return status;
}

static bt_status_t
bt_hf_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
    [OPCODE_CONNECT] = opcode_connect,
    [OPCODE_DISCONNECT] = opcode_disconnect,
    [OPCODE_CONNECT_AUDIO] = opcode_connect_audio,
    [OPCODE_DISCONNECT_AUDIO] = opcode_disconnect_audio,
    [OPCODE_START_VOICE_RECOGNITION] = opcode_start_voice_recognition,
    [OPCODE_STOP_VOICE_RECOGNITION] = opcode_stop_voice_recognition,
    [OPCODE_VOLUME_CONTROL] = opcode_volume_control,
    [OPCODE_DEVICE_STATUS_NOTIFICATION] = opcode_device_status_notification,
    [OPCODE_COPS_RESPONSE] = opcode_cops_response,
    [OPCODE_CIND_RESPONSE] = opcode_cind_response,
    [OPCODE_FORMATTED_AT_RESPONSE] = opcode_formatted_at_response,
    [OPCODE_AT_RESPONSE] = opcode_at_response,
    [OPCODE_CLCC_RESPONSE] = opcode_clcc_response,
    [OPCODE_PHONE_STATE_CHANGE] = opcode_phone_state_change
  };

  return handle_pdu_by_opcode(cmd, handler);
}

bt_status_t
(*register_bt_hf(unsigned char mode ATTRIBS(UNUSED),
                 void (*send_pdu_cb)(struct pdu_wbuf*)))(const struct pdu*)
{
  static bthf_callbacks_t bthf_callbacks = {
    .size = sizeof(bthf_callbacks),
    .connection_state_cb = connection_state_cb,
    .audio_state_cb = audio_state_cb,
    .vr_cmd_cb = vr_cmd_cb,
    .answer_call_cmd_cb = answer_call_cmd_cb,
    .hangup_call_cmd_cb = hangup_call_cmd_cb,
    .volume_cmd_cb = volume_cmd_cb,
    .dial_call_cmd_cb = dial_call_cmd_cb,
    .dtmf_cmd_cb = dtmf_cmd_cb,
    .nrec_cmd_cb = nrec_cmd_cb,
    .chld_cmd_cb = chld_cmd_cb,
    .cnum_cmd_cb = cnum_cmd_cb,
    .cind_cmd_cb = cind_cmd_cb,
    .cops_cmd_cb = cops_cmd_cb,
    .clcc_cmd_cb = clcc_cmd_cb,
    .unknown_at_cmd_cb = unknown_at_cmd_cb,
    .key_pressed_cmd_cb = key_pressed_cmd_cb
  };

  if (init_bt_hf(&bthf_callbacks) < 0)
    return NULL;

  send_pdu = send_pdu_cb;

  return bt_hf_handler;
}

int
unregister_bt_hf()
{
  uninit_bt_hf();
  return 0;
}
