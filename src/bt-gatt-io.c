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

#if ANDROID_VERSION < 19
#error GATT support requires an Android SDK version of 19 or later
#endif

#include <assert.h>
#include <fdio/task.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_gatt.h>
#include "compiler.h"
#include "log.h"
#include "bt-proto.h"
#include "bt-pdubuf.h"
#include "bt-core-io.h"
#include "bt-gatt-io.h"

enum {
  /* commands/responses */
  OPCODE_CLIENT_REGISTER = 0x01,
  OPCODE_CLIENT_UNREGISTER = 0x02,
  OPCODE_CLIENT_SCAN = 0x03,
  OPCODE_CLIENT_CONNECT_DEVICE = 0x04,
  OPCODE_CLIENT_DISCONNECT_DEVICE = 0x05,
  OPCODE_CLIENT_LISTEN = 0x06,
  OPCODE_CLIENT_REFRESH = 0x07,
  OPCODE_CLIENT_SEARCH_SERVICE= 0x08,
  OPCODE_CLIENT_GET_INCLUDED_SERVICES = 0x09,
  OPCODE_CLIENT_GET_CHARACTERISTIC =  0x0a,
  OPCODE_CLIENT_GET_DESCRIPTOR = 0x0b,
  OPCODE_CLIENT_READ_CHARACTERISTIC = 0x0c,
  OPCODE_CLIENT_WRITE_CHARACTERISTIC = 0x0d,
  OPCODE_CLIENT_READ_DESCRIPTOR = 0x0e,
  OPCODE_CLIENT_WRITE_DESCRIPTOR = 0x0f,
  OPCODE_CLIENT_EXECUTE_WRITE = 0x10,
  OPCODE_CLIENT_REGISTER_FOR_NOTIFICATION = 0x11,
  OPCODE_CLIENT_DEREGISTER_FOR_NOTIFICATION = 0x12,
  OPCODE_CLIENT_READ_REMOTE_RSSI = 0x13,
  OPCODE_CLIENT_GET_DEVICE_TYPE = 0x14,
  OPCODE_CLIENT_SET_ADVERTISING_DATA = 0x15,
  OPCODE_CLIENT_TEST_COMMAND = 0x16,
  OPCODE_SERVER_REGISTER_COMMAND = 0x17,
  OPCODE_SERVER_UNREGISTER_COMMAND = 0x18,
  OPCODE_SERVER_CONNECT_PERIPHERIAL = 0x19,
  OPCODE_SERVER_DISCONNECT_PERIPHERIAL = 0x1a,
  OPCODE_SERVER_ADD_SERVICE = 0x1b,
  OPCODE_SERVER_ADD_INCLUDED_SERVICE = 0x1c,
  OPCODE_SERVER_ADD_CHARACTERISTIC = 0x1d,
  OPCODE_SERVER_ADD_DESCRIPTOR = 0x1e,
  OPCODE_SERVER_START_SERVICE = 0x1f,
  OPCODE_SERVER_STOP_SERVICE = 0x20,
  OPCODE_SERVER_DELETE_SERVICE = 0x21,
  OPCODE_SERVER_SEND_INDICATION = 0x22,
  OPCODE_SERVER_SEND_RESPONSE = 0x23,
#if ANDROID_VERSION >= 21
  OPCODE_CLIENT_SCAN_FILTER_PARAMS_SETUP = 0x24,
  OPCODE_CLIENT_SCAN_FILTER_ADD_REMOVE = 0x25,
  OPCODE_CLIENT_SCAN_FILTER_CLEAR = 0x26,
  OPCODE_CLIENT_SCAN_FILTER_ENABLE = 0x27,
  OPCODE_CLIENT_CONFIGURE_MTU = 0x28,
  OPCODE_CLIENT_CONNECTION_PARAMETER_UPDATE = 0x29,
  OPCODE_CLIENT_SET_SCAN_PARAMETERS = 0x2a,
  OPCODE_CLIENT_SETUP_MULTI_ADVERTISING = 0x2b,
  OPCODE_CLIENT_UPDATE_MULTI_ADVERTISING = 0x2c,
  OPCODE_CLIENT_SETUP_MULTI_ADVERTISING_INSTANCE = 0x2d,
  OPCODE_CLIENT_DISABLE_MULTI_ADVERTISING_INSTANCE = 0x2e,
  OPCODE_CLIENT_CONFIGURE_BATCHSCAN = 0x2f,
  OPCODE_CLIENT_ENABLE_BATCHSCAN = 0x30,
  OPCODE_CLIENT_DISABLE_BATCHSCAN = 0x31,
  OPCODE_CLIENT_READ_BATCHSCAN_REPORTS = 0x32,
#endif
  /* notifications */
  OPCODE_CLIENT_REGISTER_NTF = 0x81,
  OPCODE_CLIENT_SCAN_RESULT_NTF = 0x82,
  OPCODE_CLIENT_CONNECT_DEVICE_NTF = 0x83,
  OPCODE_CLIENT_DISCONNECT_DEVICE_NTF = 0x84,
  OPCODE_CLIENT_SEARCH_COMPLETE_NTF = 0x85,
  OPCODE_CLIENT_SEARCH_RESULT_NTF = 0x86,
  OPCODE_CLIENT_GET_CHARACTERISTIC_NTF = 0x87,
  OPCODE_CLIENT_GET_DESCRIPTOR_NTF = 0x88,
  OPCODE_CLIENT_GET_INCLUDED_SERVICE_NTF = 0x89,
  OPCODE_CLIENT_REGISTER_FOR_NOTIFICATION_NTF = 0x8a,
  OPCODE_CLIENT_NOTIFY_NTF = 0x8b,
  OPCODE_CLIENT_READ_CHARACTERISTIC_NTF = 0x8c,
  OPCODE_CLIENT_WRITE_CHARACTERISTIC_NTF = 0x8d,
  OPCODE_CLIENT_READ_DESCRIPTOR_NTF = 0x8e,
  OPCODE_CLIENT_WRITE_DESCRIPTOR_NTF = 0x8f,
  OPCODE_CLIENT_EXECUTE_WRITE_NTF = 0x90,
  OPCODE_CLIENT_READ_REMOTE_RSSI_NTF = 0x91,
  OPCODE_CLIENT_LISTEN_NTF = 0x92,
  OPCODE_SERVER_REGISTER_NTF = 0x93,
  OPCODE_SERVER_CONNECTION_NTF = 0x94,
  OPCODE_SERVER_SERVICE_ADDED_NTF = 0x95,
  OPCODE_SERVER_INCLUDED_SERVICE_ADDED_NTF = 0x96,
  OPCODE_SERVER_CHARACTERISTIC_ADDED_NTF = 0x97,
  OPCODE_SERVER_DESCRIPTOR_ADDED_NTF = 0x98,
  OPCODE_SERVER_SERVICE_STARTED_NTF = 0x99,
  OPCODE_SERVER_SERVICE_STOPPED_NTF = 0x9a,
  OPCODE_SERVER_SERVICE_DELETED_NTF = 0x9b,
  OPCODE_SERVER_REQUEST_READ_NTF = 0x9c,
  OPCODE_SERVER_REQUEST_WRITE_NTF = 0x9d,
  OPCODE_SERVER_REQUEST_EXECUTE_WRITE_NTF = 0x9e,
  OPCODE_SERVER_RESPONSE_CONFIRMATION_NTF = 0x9f,
#if ANDROID_VERSION >= 21
  OPCODE_CLIENT_CONFIGURE_MTU_NTF = 0xa0,
  OPCODE_CLIENT_SCAN_FILTER_CONFIGURATION_NTF = 0xa1,
  OPCODE_CLIENT_SCAN_FILTER_PARAMETERS_NTF = 0xa2,
  OPCODE_CLIENT_SCAN_FILTER_STATUS_NTF = 0xa3,
  OPCODE_CLIENT_MULTI_ADVERTISING_ENABLE_NTF = 0xa4,
  OPCODE_CLIENT_MULTI_ADVERTISING_UPDATE_NTF = 0xa5,
  OPCODE_CLIENT_MULTI_ADVERTISING_DATA_NTF = 0xa6,
  OPCODE_CLIENT_MULTI_ADVERTISING_DISABLE_NTF = 0xa7,
  OPCODE_CLIENT_CONGESTION_NTF = 0xa8,
  OPCODE_CLIENT_CONFIGURE_BATCHSCAN_NTF = 0xa9,
  OPCODE_CLIENT_ENABLE_BATCHSCAN_NTF = 0xaa,
  OPCODE_CLIENT_BATCHSCAN_REPORTS_NTF = 0xab,
  OPCODE_CLIENT_BATCHSCAN_THRESHOLD_NTF = 0xac,
  OPCODE_CLIENT_TRACK_ADV_EVENT_NTF = 0xad,
  OPCODE_SERVER_INDICATION_SENT_NTF = 0xae,
  OPCODE_SERVER_CONGESTION_NTF = 0xaf
#endif
#if ANDROID_VERSION >= 22
  ,
  OPCODE_SERVER_MTU_CHANGED_NTF = 0xb0
#endif
};

static void (*send_pdu)(struct pdu_wbuf* wbuf);
static const btgatt_interface_t* btgatt_interface;

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
append_btgatt_gatt_id_t(struct pdu* pdu, const btgatt_gatt_id_t* gatt_id)
{
  if (append_bt_uuid_t(pdu, &gatt_id->uuid) < 0)
    return -1;
  return append_to_pdu(pdu, "C", gatt_id->inst_id);
}

static long
append_btgatt_srvc_id_t(struct pdu* pdu, const btgatt_srvc_id_t* srvc_id)
{
  if (append_btgatt_gatt_id_t(pdu, &srvc_id->id) < 0)
    return -1;
  return append_to_pdu(pdu, "C", srvc_id->is_primary);
}

static long
append_btgatt_notify_params_t(struct pdu* pdu,
                              const btgatt_notify_params_t* params)
{
  if ((append_bt_bdaddr_t(pdu, &params->bda) < 0) ||
      (append_btgatt_srvc_id_t(pdu, &params->srvc_id) < 0) ||
      (append_btgatt_gatt_id_t(pdu, &params->char_id) < 0))
    return -1;
  return append_to_pdu(pdu, "CSm", params->is_notify, params->len,
                                   params->value, (size_t)params->len);
}

static long
append_btgatt_unformatted_value_t(struct pdu* pdu,
                                  const btgatt_unformatted_value_t* value)
{
  return append_to_pdu(pdu, "Sm", value->len, value->value,
                                  (size_t)value->len);
}

static long
append_btgatt_read_params_t(struct pdu* pdu,
                            const btgatt_read_params_t* params)
{
  if ((append_btgatt_srvc_id_t(pdu, &params->srvc_id) < 0) ||
      (append_btgatt_gatt_id_t(pdu, &params->char_id) < 0) ||
      (append_btgatt_gatt_id_t(pdu, &params->descr_id) < 0) ||
      (append_to_pdu(pdu, "CS", params->status, params->value_type) < 0))
    return -1;
  return append_btgatt_unformatted_value_t(pdu, &params->value);
}

static long
append_btgatt_write_params_t(struct pdu* pdu,
                             const btgatt_write_params_t* params)
{
  if ((append_btgatt_srvc_id_t(pdu, &params->srvc_id) < 0) ||
      (append_btgatt_gatt_id_t(pdu, &params->char_id) < 0) ||
      (append_btgatt_gatt_id_t(pdu, &params->descr_id) < 0))
    return -1;
  return append_to_pdu(pdu, "C", params->status);
}

/*
 * Notifications
 */

static void
client_register_client_cb(int status, int client_if, bt_uuid_t* app_uuid)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4 + /* client */
                         16, /* UUID */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_REGISTER_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)status,
                                           (int32_t)client_if) < 0) ||
      (append_bt_uuid_t(&wbuf->buf.pdu, app_uuid) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_scan_result_cb(bt_bdaddr_t* bd_addr, int rssi, uint8_t* adv_data)
{
  size_t len;
  struct pdu_wbuf* wbuf;

  if (adv_data) {
    len = strlen((const char*)adv_data);
    if (len > USHRT_MAX) {
      ALOGE("data too long");
      return;
    }
  } else {
    len = 0;
  }

  wbuf = create_pdu_wbuf(6 + /* address */
                         4 + /* RSSI */
                         2 + /* data length */
                         len, /* data */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_SCAN_RESULT_NTF);
  if ((append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "iSm", (int32_t)rssi,
                                            (uint16_t)len,
                                            adv_data, len) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_open_cb(int conn_id, int status, int client_if, bt_bdaddr_t* bd_addr)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status */
                         4 + /* client */
                         6, /* address */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_CONNECT_DEVICE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)conn_id,
                                            (int32_t)status,
                                            (int32_t)client_if) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_close_cb(int conn_id, int status, int client_if, bt_bdaddr_t* bd_addr)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status */
                         4 + /* client */
                         6, /* address */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_DISCONNECT_DEVICE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)conn_id,
                                            (int32_t)status,
                                            (int32_t)client_if) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_search_complete_cb(int conn_id, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_SEARCH_COMPLETE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)status) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_search_result_cb(int conn_id, btgatt_srvc_id_t* srvc_id)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         18, /* GATT service ID */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_SEARCH_RESULT_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "i", (int32_t)conn_id) < 0) ||
      (append_btgatt_srvc_id_t(&wbuf->buf.pdu, srvc_id) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_get_characteristic_cb(int conn_id, int status,
                             btgatt_srvc_id_t* srvc_id,
                             btgatt_gatt_id_t* char_id, int char_prop)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status */
                         18 + /* service ID */
                         17 + /* characterisic ID */
                         4, /* char prop */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_GET_CHARACTERISTIC_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)status) < 0) ||
      (append_btgatt_srvc_id_t(&wbuf->buf.pdu, srvc_id) < 0) ||
      (append_btgatt_gatt_id_t(&wbuf->buf.pdu, char_id) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "i", (int32_t)char_prop) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_get_descriptor_cb(int conn_id, int status,
                         btgatt_srvc_id_t* srvc_id,
                         btgatt_gatt_id_t* char_id,
                         btgatt_gatt_id_t* descr_id)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status */
                         18 + /* GATT service ID */
                         17 + /* GATT characteristic ID */
                         17, /* GATT descriptor ID */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_GET_DESCRIPTOR_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)status) < 0) ||
      (append_btgatt_srvc_id_t(&wbuf->buf.pdu, srvc_id) < 0) ||
      (append_btgatt_gatt_id_t(&wbuf->buf.pdu, char_id) < 0) ||
      (append_btgatt_gatt_id_t(&wbuf->buf.pdu, descr_id) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_get_included_service_cb(int conn_id, int status,
                               btgatt_srvc_id_t* srvc_id,
                               btgatt_srvc_id_t* incl_srvc_id)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status */
                         18 + /* GATT service ID */
                         18, /* GATT included service ID */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_GET_INCLUDED_SERVICE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)status) < 0) ||
      (append_btgatt_srvc_id_t(&wbuf->buf.pdu, srvc_id) < 0) ||
      (append_btgatt_srvc_id_t(&wbuf->buf.pdu, incl_srvc_id) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_register_for_notification_cb(int conn_id, int registered, int status,
                                    btgatt_srvc_id_t* srvc_id,
                                    btgatt_gatt_id_t* char_id)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* registered */
                         4 + /* status */
                         18 + /* GATT service ID */
                         17, /* GATT characteristic ID */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_REGISTER_FOR_NOTIFICATION_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)conn_id,
                                            (int32_t)registered,
                                            (int32_t)status) < 0) ||
      (append_btgatt_srvc_id_t(&wbuf->buf.pdu, srvc_id) < 0) ||
      (append_btgatt_gatt_id_t(&wbuf->buf.pdu, char_id) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_notify_cb(int conn_id, btgatt_notify_params_t* p_data)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         44 + p_data->len, /* GATT notify parameters */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_NOTIFY_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "i", (int32_t)conn_id) < 0) ||
      (append_btgatt_notify_params_t(&wbuf->buf.pdu, p_data) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_read_characteristic_cb(int conn_id, int status,
                              btgatt_read_params_t* p_data)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status ID */
                         59 + p_data->value.len, /* GATT read parameters */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_READ_CHARACTERISTIC_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)status) < 0) ||
      (append_btgatt_read_params_t(&wbuf->buf.pdu, p_data) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_write_characteristic_cb(int conn_id, int status,
                               btgatt_write_params_t* p_data)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status */
                         53, /* GATT write parameters*/
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_WRITE_CHARACTERISTIC_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)status) < 0) ||
      (append_btgatt_write_params_t(&wbuf->buf.pdu, p_data) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_read_descriptor_cb(int conn_id, int status,
                          btgatt_read_params_t* p_data)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status ID */
                         59 + p_data->value.len, /* GATT read parameters */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_READ_DESCRIPTOR_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)status) < 0) ||
      (append_btgatt_read_params_t(&wbuf->buf.pdu, p_data) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_write_descriptor_cb(int conn_id, int status,
                           btgatt_write_params_t* p_data)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status */
                         53, /* GATT write parameters*/
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_WRITE_DESCRIPTOR_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)status) < 0) ||
      (append_btgatt_write_params_t(&wbuf->buf.pdu, p_data) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_execute_write_cb(int conn_id, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_EXECUTE_WRITE_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                          (int32_t)status) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_read_remote_rssi_cb(int client_if, bt_bdaddr_t* bd_addr, int rssi,
                           int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* client */
                         6 + /* address */
                         4 + /* RSSI */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_READ_REMOTE_RSSI_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "i", (int32_t)client_if) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)rssi,
                                           (int32_t)status) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_listen_cb(int status, int server_if)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4, /* server */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_LISTEN_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)status,
                                          (int32_t)server_if) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

#if ANDROID_VERSION >= 21
static void
client_configure_mtu_cb(int conn_id, int status, int mtu)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* status */
                         4, /* MTU */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_CONFIGURE_MTU_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)conn_id,
                                           (int32_t)status,
                                           (int32_t)conn_id) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_scan_filter_cfg_cb(int action, int client_if, int status,
                          int filt_type, int avbl_space)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* action */
                         4 + /* client */
                         4 + /* status */
                         4 + /* filter type */
                         4, /* available space */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_SCAN_FILTER_CONFIGURATION_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iiiii", (int32_t)action,
                                             (int32_t)client_if,
                                             (int32_t)status,
                                             (int32_t)filt_type,
                                             (int32_t)avbl_space) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_scan_filter_param_cb(int action, int client_if, int status,
                            int avbl_space)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* action */
                         4 + /* client */
                         4 + /* status */
                         4, /* available space */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_SCAN_FILTER_PARAMETERS_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iiii", (int32_t)action,
                                            (int32_t)client_if,
                                            (int32_t)status,
                                            (int32_t)avbl_space) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_scan_filter_status_cb(int enable, int client_if, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* enable */
                         4 + /* client */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_SCAN_FILTER_STATUS_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)enable,
                                           (int32_t)client_if,
                                           (int32_t)status) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_multi_adv_enable_cb(int client_if, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* client */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_MULTI_ADVERTISING_ENABLE_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)client_if,
                                          (int32_t)status) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_multi_adv_update_cb(int client_if, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* client */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_MULTI_ADVERTISING_UPDATE_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)client_if,
                                          (int32_t)status) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_multi_adv_data_cb(int client_if, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* client */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_MULTI_ADVERTISING_DATA_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)client_if,
                                          (int32_t)status) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_multi_adv_disable_cb(int client_if, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* client */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_MULTI_ADVERTISING_DISABLE_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)client_if,
                                          (int32_t)status) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_congestion_cb(int conn_id, bool congested)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         1, /* congested */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_CONGESTION_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iC", (int32_t)conn_id,
                                          (uint8_t)congested) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_batchscan_cfg_storage_cb(int client_if, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* client */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_CONFIGURE_BATCHSCAN_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)client_if,
                                          (int32_t)status) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_batchscan_enb_disable_cb(int action, int client_if, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* action */
                         4 + /* client */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_ENABLE_BATCHSCAN_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)action,
                                           (int32_t)client_if,
                                           (int32_t)status) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_batchscan_reports_cb(int client_if, int status, int report_format,
                            int num_records, int data_len, uint8_t* rep_data)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* client */
                         4 + /* status */
                         4 + /* report format*/
                         4 + /* number of records */
                         4 + /* length */
                         data_len, /* data */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu,
           SERVICE_BT_GATT,
           OPCODE_CLIENT_BATCHSCAN_REPORTS_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iiiiim", (int32_t)client_if,
                                              (int32_t)status,
                                              (int32_t)report_format,
                                              (int32_t)num_records,
                                              (int32_t)data_len,
                                              rep_data, (size_t)data_len) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_batchscan_threshold_cb(int client_if)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4, /* client */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_CLIENT_BATCHSCAN_THRESHOLD_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "i", (int32_t)client_if) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
client_track_adv_event_cb(int client_if, int filt_index, int addr_type,
                          bt_bdaddr_t* bd_addr, int adv_state)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* client */
                         4 + /* filter index */
                         4 + /* address type */
                         6 + /* address */
                         4, /* adv state */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_CLIENT_TRACK_ADV_EVENT_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)client_if,
                                            (int32_t)filt_index,
                                            (int32_t)addr_type) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "i", (int32_t)adv_state) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}
#endif

static void
server_register_server_cb(int status, int server_if,
                          bt_uuid_t* app_uuid)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4 + /* server */
                         16, /* UUID */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_SERVER_REGISTER_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)status,
                                           (int32_t)server_if) < 0) ||
      (append_bt_uuid_t(&wbuf->buf.pdu, app_uuid) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_connection_cb(int conn_id, int server_if, int connected,
                     bt_bdaddr_t* bd_addr)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* server */
                         4 + /* connected */
                         6, /* address */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_SERVER_CONNECTION_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)conn_id,
                                            (int32_t)server_if,
                                            (int32_t)connected) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_service_added_cb(int status, int server_if, btgatt_srvc_id_t *srvc_id,
                        int srvc_handle)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4 + /* server */
                         18 + /* GATT service ID */
                         4, /* service handle */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT, OPCODE_SERVER_SERVICE_ADDED_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)status,
                                           (int32_t)server_if) < 0) ||
      (append_btgatt_srvc_id_t(&wbuf->buf.pdu, srvc_id) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "i", (int32_t)srvc_handle) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_included_service_added_cb(int status, int server_if, int srvc_handle,
                                 int incl_srvc_handle)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4 + /* server */
                         4 + /* service handle */
                         4, /* included service handle */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_INCLUDED_SERVICE_ADDED_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iiii", (int32_t)status,
                                            (int32_t)server_if,
                                            (int32_t)srvc_handle,
                                            (int32_t)incl_srvc_handle) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_characteristic_added_cb(int status, int server_if, bt_uuid_t* uuid,
                               int srvc_handle, int char_handle)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4 + /* server */
                         16 + /* UUID */
                         4 + /* service handle */
                         4, /* characteristic handle */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_CHARACTERISTIC_ADDED_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)status,
                                           (int32_t)server_if) < 0) ||
      (append_bt_uuid_t(&wbuf->buf.pdu, uuid) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)srvc_handle,
                                           (int32_t)char_handle) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_descriptor_added_cb(int status, int server_if, bt_uuid_t* uuid,
                           int srvc_handle, int descr_handle)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4 + /* server */
                         16 + /* UUID */
                         4 + /* service handle */
                         4, /* description handle */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_DESCRIPTOR_ADDED_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)status,
                                           (int32_t)server_if) < 0) ||
      (append_bt_uuid_t(&wbuf->buf.pdu, uuid) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)srvc_handle,
                                           (int32_t)descr_handle) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_service_started_cb(int status, int server_if, int srvc_handle)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4 + /* server */
                         4, /* service handle */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_SERVICE_STARTED_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)status,
                                           (int32_t)server_if,
                                           (int32_t)srvc_handle) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_service_stopped_cb(int status, int server_if, int srvc_handle)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4 + /* server */
                         4, /* service handle */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_SERVICE_STOPPED_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)status,
                                           (int32_t)server_if,
                                           (int32_t)srvc_handle) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_service_deleted_cb(int status, int server_if, int srvc_handle)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4 + /* server */
                         4, /* service handle */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_SERVICE_DELETED_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iii", (int32_t)status,
                                           (int32_t)server_if,
                                           (int32_t)srvc_handle) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_request_read_cb(int conn_id, int trans_id, bt_bdaddr_t* bd_addr,
                       int attr_handle, int offset, bool is_long)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* trans ID */
                         6 + /* address */
                         4 + /* attribute handle */
                         4 + /* offset */
                         1, /* is long */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_REQUEST_READ_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)trans_id) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "iiC", (int32_t)attr_handle,
                                            (int32_t)offset,
                                            (uint8_t)is_long) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_request_write_cb(int conn_id, int trans_id, bt_bdaddr_t* bd_addr,
                        int attr_handle, int offset, int length,
                        bool need_rsp, bool is_prep, uint8_t* value)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* trans ID */
                         6 + /* address */
                         4 + /* attribute handle */
                         4 + /* offset */
                         4 + /* length */
                         1 + /* need response */
                         1 + /* is prepare */
                         length, /* value */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_REQUEST_WRITE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)trans_id) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "iiiCCm", (int32_t)attr_handle,
                                               (int32_t)offset,
                                               (int32_t)length,
                                               (uint8_t)need_rsp,
                                               (uint8_t)is_prep,
                                               value,
                                               (size_t)length) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_request_exec_write_cb(int conn_id, int trans_id, bt_bdaddr_t* bd_addr,
                             int exec_write)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4 + /* trans ID */
                         6 + /* address */
                         4, /* execute write */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_REQUEST_EXECUTE_WRITE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                           (int32_t)trans_id) < 0) ||
      (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "i", (int32_t)exec_write) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_response_confirmation_cb(int status, int handle)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* status */
                         4, /* handle */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_RESPONSE_CONFIRMATION_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)status,
                                          (int32_t)handle) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

#if ANDROID_VERSION >= 21
static void
server_indication_sent_cb(int conn_id, int status)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4, /* status */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_INDICATION_SENT_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                          (int32_t)status) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
server_congestion_cb(int conn_id, bool congested)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         1, /* congested */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_CONGESTION_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "iC", (int32_t)conn_id,
                                          (uint8_t)congested) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}
#endif

#if ANDROID_VERSION >= 22
static void
server_mtu_changed_cb(int conn_id, int mtu)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(4 + /* connection ID */
                         4, /* MTU */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_GATT,
           OPCODE_SERVER_MTU_CHANGED_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "ii", (int32_t)conn_id,
                                          (int32_t)mtu) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}
#endif

/*
 * Commands/Responses
 */

static bt_status_t
bt_gatt_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
  };

  return handle_pdu_by_opcode(cmd, handler);
}

bt_status_t
(*register_bt_gatt(unsigned char mode ATTRIBS(UNUSED),
                   unsigned long max_num_clients ATTRIBS(UNUSED),
                   void (*send_pdu_cb)(struct pdu_wbuf*)))(const struct pdu*)
{
  static btgatt_client_callbacks_t btgatt_client_callbacks = {
    .register_client_cb = client_register_client_cb,
    .scan_result_cb = client_scan_result_cb,
    .open_cb = client_open_cb,
    .close_cb = client_close_cb,
    .search_complete_cb = client_search_complete_cb,
    .search_result_cb = client_search_result_cb,
    .get_characteristic_cb = client_get_characteristic_cb,
    .get_descriptor_cb = client_get_descriptor_cb,
    .get_included_service_cb = client_get_included_service_cb,
    .register_for_notification_cb = client_register_for_notification_cb,
    .notify_cb = client_notify_cb,
    .read_characteristic_cb = client_read_characteristic_cb,
    .write_characteristic_cb = client_write_characteristic_cb,
    .read_descriptor_cb = client_read_descriptor_cb,
    .write_descriptor_cb = client_write_descriptor_cb,
    .execute_write_cb = client_execute_write_cb,
    .read_remote_rssi_cb = client_read_remote_rssi_cb,
    .listen_cb = client_listen_cb,
#if ANDROID_VERSION >= 21
    .configure_mtu_cb = client_configure_mtu_cb,
    .scan_filter_cfg_cb = client_scan_filter_cfg_cb,
    .scan_filter_param_cb = client_scan_filter_param_cb,
    .scan_filter_status_cb = client_scan_filter_status_cb,
    .multi_adv_enable_cb = client_multi_adv_enable_cb,
    .multi_adv_update_cb = client_multi_adv_update_cb,
    .multi_adv_data_cb = client_multi_adv_data_cb,
    .multi_adv_disable_cb = client_multi_adv_disable_cb,
    .congestion_cb = client_congestion_cb,
    .batchscan_cfg_storage_cb = client_batchscan_cfg_storage_cb,
    .batchscan_enb_disable_cb = client_batchscan_enb_disable_cb,
    .batchscan_reports_cb = client_batchscan_reports_cb,
    .batchscan_threshold_cb = client_batchscan_threshold_cb,
    .track_adv_event_cb = client_track_adv_event_cb
#endif
  };

  static btgatt_server_callbacks_t btgatt_server_callbacks = {
    .register_server_cb = server_register_server_cb,
    .connection_cb = server_connection_cb,
    .service_added_cb = server_service_added_cb,
    .included_service_added_cb = server_included_service_added_cb,
    .characteristic_added_cb = server_characteristic_added_cb,
    .descriptor_added_cb = server_descriptor_added_cb,
    .service_started_cb = server_service_started_cb,
    .service_stopped_cb = server_service_stopped_cb,
    .service_deleted_cb = server_service_deleted_cb,
    .request_read_cb = server_request_read_cb,
    .request_write_cb = server_request_write_cb,
    .request_exec_write_cb = server_request_exec_write_cb,
    .response_confirmation_cb = server_response_confirmation_cb,
#if ANDROID_VERSION >= 21
    .indication_sent_cb = server_indication_sent_cb,
    .congestion_cb = server_congestion_cb,
#endif
#if ANDROID_VERSION >= 22
    .mtu_changed_cb = server_mtu_changed_cb
#endif
  };

  static btgatt_callbacks_t btgatt_callbacks = {
    .size = sizeof(btgatt_callbacks),
    .client = &btgatt_client_callbacks,
    .server = &btgatt_server_callbacks
  };

  bt_status_t status;

  if (btgatt_interface) {
    ALOGE("GATT interface already set up");
    return NULL;
  }

  btgatt_interface = get_profile_interface(BT_PROFILE_GATT_ID);
  if (!btgatt_interface) {
    ALOGE("get_profile_interface(BT_PROFILE_GATT_ID) failed");
    return NULL;
  }

  assert(btgatt_interface->init);
  status = btgatt_interface->init(&btgatt_callbacks);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("btgatt_interface_t::init failed");
    return NULL;
  }

  send_pdu = send_pdu_cb;

  return bt_gatt_handler;
}

int
unregister_bt_gatt()
{
  assert(btgatt_interface);
  assert(btgatt_interface->cleanup);

  btgatt_interface->cleanup();
  btgatt_interface = NULL;

  return 0;
}
