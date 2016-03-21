/*
 * Copyright (C) 2016  Mozilla Foundation
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
#include <hardware/bt_hh.h>
#include <pdu/pdubuf.h>
#include <stdlib.h>
#include "compiler.h"
#include "log.h"
#include "bt-proto.h"
#include "bt-core-io.h"
#include "bt-hh-io.h"

enum {
  /* commands/responses */
  OPCODE_CONNECT = 0x01,
  OPCODE_DISCONNECT = 0x02,
  OPCODE_VIRTUAL_UNPLUG = 0x03,
  OPCODE_SET_INFO = 0x04,
  OPCODE_GET_PROTOCOL = 0x05,
  OPCODE_SET_PROTOCOL = 0x06,
  OPCODE_GET_REPORT = 0x07,
  OPCODE_SET_REPORT = 0x08,
  OPCODE_SEND_DATA = 0x09,
  /* notifications */
  OPCODE_CONNECTION_STATE_NTF = 0x81,
  OPCODE_HID_INFO_NTF = 0x82,
  OPCODE_PROTOCOL_MODE_NTF = 0x83,
  OPCODE_IDLE_TIME_NTF = 0x84,
  OPCODE_GET_REPORT_NTF = 0x85,
  OPCODE_VIRTUAL_UNPLUG_NTF = 0x86
#if ANDROID_VERSION >= 21
  ,
  OPCODE_HANDSHAKE_NTF = 0x87
#endif
};

static void (*send_pdu)(struct pdu_wbuf* wbuf);
static const bthh_interface_t* bthh_interface;

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
 * Protocol helpers
 */

static long
read_bthh_hid_info_t(const struct pdu* pdu, unsigned long offset,
                     bthh_hid_info_t* hid_info)
{
  long off;
  uint8_t sub_class, app_id, ctry_code;
  uint16_t attr_mask, vendor_id, product_id, version, dl_len;

  off = read_pdu_at(pdu, offset, "SCCSSSCS", &attr_mask, &sub_class,
                                             &app_id, &vendor_id,
                                             &product_id, &version,
                                             &ctry_code, &dl_len);
  if (off < 0)
    return -1;

  hid_info->attr_mask = attr_mask;
  hid_info->sub_class = sub_class;
  hid_info->app_id = app_id;
  hid_info->vendor_id = vendor_id;
  hid_info->product_id = product_id;
  hid_info->version = version;
  hid_info->ctry_code = ctry_code;
#ifdef Q_BLUETOOTH
  // Set to default priority PRIORITY_ON = 100
  hid_info->priority = 100;
#endif
  hid_info->dl_len = dl_len;

  if (hid_info->dl_len > BTHH_MAX_DSC_LEN) {
    ALOGE("dl_len is too long");
    return -1;
  }

  return read_pdu_at(pdu, off, "M", &hid_info->dsc_list, BTHH_MAX_DSC_LEN);
}

static long
append_bthh_hid_info_t(struct pdu* pdu, const bthh_hid_info_t* hid_info)
{
  static const uint8_t padding[BTHH_MAX_DSC_LEN];

  if (append_to_pdu(pdu, "SCCSSSCS", (uint16_t)hid_info->attr_mask,
                                     (uint8_t)hid_info->sub_class,
                                     (uint8_t)hid_info->app_id,
                                     (uint16_t)hid_info->vendor_id,
                                     (uint16_t)hid_info->product_id,
                                     (uint16_t)hid_info->version,
                                     (uint8_t)hid_info->ctry_code,
                                     (uint16_t)hid_info->dl_len) < 0)
    return -1;

  if (hid_info->dl_len > BTHH_MAX_DSC_LEN) {
    ALOGE("dl_len is too long");
    return -1;
  }

  return append_to_pdu(pdu, "mm", hid_info->dsc_list, hid_info->dl_len,
                                  padding, BTHH_MAX_DSC_LEN - hid_info->dl_len);
}

/*
 * Notifications
 */

static void
connection_state_cb(bt_bdaddr_t* bd_addr, bthh_connection_state_t state)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* address */
                         1, /* connection state */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HH, OPCODE_CONNECTION_STATE_NTF);
  if ((append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  destroy_pdu_wbuf(wbuf);
}

static void
hid_info_cb(bt_bdaddr_t* bd_addr, bthh_hid_info_t hid_info)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* address */
                         27 + BTHH_MAX_DSC_LEN, /* hid info */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HH, OPCODE_HID_INFO_NTF);
  if ((append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_bthh_hid_info_t(&wbuf->buf.pdu, &hid_info) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  destroy_pdu_wbuf(wbuf);
}

static void
protocol_mode_cb(bt_bdaddr_t* bd_addr, bthh_status_t hh_status,
                 bthh_protocol_mode_t mode)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* address */
                         1 + /* HH status */
                         1, /* protocol mode */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HH, OPCODE_PROTOCOL_MODE_NTF);
  if ((append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "CC", (uint8_t)hh_status,
                                           (uint8_t)mode) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  destroy_pdu_wbuf(wbuf);
}

static void
idle_time_cb(bt_bdaddr_t* bd_addr, bthh_status_t hh_status, int idle_rate)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* address */
                         1 + /* HH status */
                         2, /* idle rate */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HH, OPCODE_IDLE_TIME_NTF);
  if  ((append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
       (append_to_pdu(&wbuf->buf.pdu, "CS", (uint8_t)hh_status,
                                            (uint16_t)idle_rate) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  destroy_pdu_wbuf(wbuf);
}

static void
get_report_cb(bt_bdaddr_t* bd_addr, bthh_status_t hh_status, uint8_t* rpt_data,
              int rpt_size)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* address */
                         1 + /* HH status */
                         2 + /* report size */
                         rpt_size, /* report data */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HH, OPCODE_GET_REPORT_NTF);
  if ((append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "CSm", (uint8_t)hh_status,
                                            (uint16_t)rpt_size, rpt_data,
                                            (size_t)rpt_size) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  destroy_pdu_wbuf(wbuf);
}

static void
virtual_unplug_cb(bt_bdaddr_t* bd_addr, bthh_status_t hh_status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* address */
                         1, /* HH status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HH, OPCODE_VIRTUAL_UNPLUG_NTF);
  if ((append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)hh_status) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  destroy_pdu_wbuf(wbuf);
}

#if ANDROID_VERSION >= 21
static void
handshake_cb(bt_bdaddr_t *bd_addr, bthh_status_t hh_status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* address */
                         1, /* HH status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_HH, OPCODE_HANDSHAKE_NTF);
  if ((append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)hh_status) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  destroy_pdu_wbuf(wbuf);
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

  assert(bthh_interface);
  assert(bthh_interface->connect);

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bthh_interface->connect(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bthh_interface_connect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bthh_interface_connect:
  destroy_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_disconnect(const struct pdu* cmd)
{
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(bthh_interface);
  assert(bthh_interface->disconnect);

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bthh_interface->disconnect(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bthh_interface_disconnect;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bthh_interface_disconnect:
  destroy_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_virtual_unplug(const struct pdu* cmd)
{
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(bthh_interface);
  assert(bthh_interface->virtual_unplug);

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bthh_interface->virtual_unplug(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bthh_interface_virtual_unplug;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bthh_interface_virtual_unplug:
  destroy_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_set_info(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  bthh_hid_info_t hid_info;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(bthh_interface);
  assert(bthh_interface->set_info);

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  if (read_bthh_hid_info_t(cmd, off, &hid_info) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bthh_interface->set_info(&bd_addr, hid_info);
  if (status !=BT_STATUS_SUCCESS)
    goto err_bthh_interface_set_info;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bthh_interface_set_info:
  destroy_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_get_protocol(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  uint8_t protocol_mode;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(bthh_interface);
  assert(bthh_interface->get_protocol);

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  off = read_pdu_at(cmd, off, "C", &protocol_mode);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bthh_interface->get_protocol(&bd_addr, protocol_mode);
  if (status != BT_STATUS_SUCCESS)
    goto err_bthh_interface_get_protocol;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bthh_interface_get_protocol:
  destroy_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_set_protocol(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  uint8_t protocol_mode;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(bthh_interface);
  assert(bthh_interface->set_protocol);

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  off = read_pdu_at(cmd, off, "C", &protocol_mode);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bthh_interface->set_protocol(&bd_addr, protocol_mode);
  if (status != BT_STATUS_SUCCESS)
    goto err_bthh_interface_set_protocol;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bthh_interface_set_protocol:
  destroy_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_get_report(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  uint8_t rpt_type, rpt_id;
  uint16_t buf_size;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(bthh_interface);
  assert(bthh_interface->get_report);

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  off = read_pdu_at(cmd, off, "CCS", &rpt_type, &rpt_id, &buf_size);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bthh_interface->get_report(&bd_addr, rpt_type, rpt_id, buf_size);

  if (status != BT_STATUS_SUCCESS)
    goto err_bthh_interface_get_report;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bthh_interface_get_report:
  destroy_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_set_report(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  uint8_t rpt_type;
  uint16_t rpt_len;
  char* rpt;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(bthh_interface);
  assert(bthh_interface->set_report);

  rpt = NULL;

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    return status;
  }

  off = read_pdu_at(cmd, off, "CS", &rpt_type, &rpt_len);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at;
  }

  off = read_pdu_at(cmd, off, "M", &rpt, (size_t)rpt_len);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = bthh_interface->set_report(&bd_addr, rpt_type, rpt);
  if (status != BT_STATUS_SUCCESS)
    goto err_bthh_interface_set_report;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(rpt);

  return BT_STATUS_SUCCESS;
err_bthh_interface_set_report:
  destroy_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
err_read_pdu_at:
  free(rpt);
  return status;
}

static bt_status_t
opcode_send_data(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  uint16_t data_len;
  char* data;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(bthh_interface);
  assert(bthh_interface->send_data);

  data = NULL;

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    return status;
  }

  off = read_pdu_at(cmd, off, "S", &data_len);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at;
  }

  off = read_pdu_at(cmd, off, "M", &data, (size_t)data_len);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = bthh_interface->send_data(&bd_addr, data);
  if (status != BT_STATUS_SUCCESS)
    goto err_bthh_interface_send_data;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(data);

  return BT_STATUS_SUCCESS;
err_bthh_interface_send_data:
  destroy_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
err_read_pdu_at:
  free(data);
  return status;
}

static bt_status_t
bt_hh_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
    [OPCODE_CONNECT] = opcode_connect,
    [OPCODE_DISCONNECT] = opcode_disconnect,
    [OPCODE_VIRTUAL_UNPLUG] = opcode_virtual_unplug,
    [OPCODE_SET_INFO] = opcode_set_info,
    [OPCODE_GET_PROTOCOL] = opcode_get_protocol,
    [OPCODE_SET_PROTOCOL] = opcode_set_protocol,
    [OPCODE_GET_REPORT] = opcode_get_report,
    [OPCODE_SET_REPORT] = opcode_set_report,
    [OPCODE_SEND_DATA] = opcode_send_data
  };

  return handle_pdu_by_opcode(cmd, handler);
}

bt_status_t
(*register_bt_hh(unsigned char mode ATTRIBS(UNUSED),
                 unsigned long max_num_clients ATTRIBS(UNUSED),
                 void (*send_pdu_cb)(struct pdu_wbuf*)))(const struct pdu*)
{
  static bthh_callbacks_t bthh_callbacks = {
    .size = sizeof(bthh_callbacks),
    .connection_state_cb = connection_state_cb,
    .hid_info_cb = hid_info_cb,
    .protocol_mode_cb = protocol_mode_cb,
    .idle_time_cb = idle_time_cb,
    .get_report_cb = get_report_cb,
    .virtual_unplug_cb = virtual_unplug_cb
#if ANDROID_VERSION >= 21
    ,
    .handshake_cb = handshake_cb
#endif
  };

  bt_status_t status;

  if (bthh_interface) {
    ALOGE("HID interface already set up");
    return NULL;
  }

  bthh_interface = get_profile_interface(BT_PROFILE_HIDHOST_ID);
  if (!bthh_interface) {
    ALOGE("get_profile_interface(BT_PROFILE_HIDHOST_ID) failed");
    return NULL;
  }

  assert(bthh_interface->init);
  status = bthh_interface->init(&bthh_callbacks);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("bthh_interface_t::init failed");
    return NULL;
  }

  send_pdu = send_pdu_cb;

  return bt_hh_handler;
}

int
unregister_bt_hh()
{
  assert(bthh_interface);
  assert(bthh_interface->cleanup);

  bthh_interface->cleanup();
  bthh_interface = NULL;

  return 0;
}
