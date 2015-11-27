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
#include <stdlib.h>
#include "compiler.h"
#include "log.h"
#include "bt-proto.h"
#include "bt-pdubuf.h"
#include "bt-core-io.h"
#include "bt-gatt-io.h"
#include "version.h"

#define MAX_ADV_DATA_LEN 62

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
read_btgatt_gatt_id_t(const struct pdu* pdu, unsigned long offset,
                      btgatt_gatt_id_t* gatt_id)
{
  long off = read_bt_uuid_t(pdu, offset, &gatt_id->uuid);
  if (off < 0) {
    return -1;
  }
  return read_pdu_at(pdu, off, "C", &gatt_id->inst_id);
}

static long
read_btgatt_srvc_id_t(const struct pdu* pdu, unsigned long offset,
                      btgatt_srvc_id_t* srvc_id)
{
  long off = read_btgatt_gatt_id_t(pdu, offset, &srvc_id->id);
  if (off < 0) {
    return -1;
  }
  return read_pdu_at(pdu, off, "C", &srvc_id->is_primary);
}

static long
read_btgatt_test_params_t(const struct pdu* pdu, unsigned long offset,
                          btgatt_test_params_t* params)
{
  params->bda1 = malloc(sizeof(params->bda1));
  if (!params->bda1) {
    ALOGE_ERRNO("malloc");
    return -1;
  }
  params->uuid1 = malloc(sizeof(params->uuid1));
  if (!params->uuid1) {
    ALOGE_ERRNO("malloc");
    return -1;
  }
  long off = read_bt_bdaddr_t(pdu, offset, params->bda1);
  if (off < 0) {
    return -1;
  }
  off = read_bt_uuid_t(pdu, off, params->uuid1);
  if (off < 0) {
    return -1;
  }
  return read_pdu_at(pdu, off, "SSSSS", &params->u1, &params->u2,
                                        &params->u3, &params->u4,
                                        &params->u5);
}

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

static void
cleanup_btgatt_test_params_t(btgatt_test_params_t* params)
{
  free(params->bda1);
  free(params->uuid1);
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
  struct pdu_wbuf* wbuf;
  size_t len = 0;

  if (adv_data) {
    /**
     * Bluetooth Core Specification, Volume 3, Part C, Section 11
     * Each AD structure shall have a Length field of one octet, which
     * contains the Length value, and a Data field of Length octets.
     * | len_1 | data_1 | len_2 | data_2 | ... | len_n | data_n | 000...000b |
     *
     * Bluedroid might also carry EIR Data in |adv_data| parameter. Since
     * EIR Data and AD Structure use the same format to carry information,
     * we parse their length in the same way to have an accurate total
     * length of |adv_data|.
     *
     * Note: The maximum size of |adv_data| is 62 bytes based on Bluedroid's
     * implementation. Although the size of EIR data is 240 bytes, only the
     * first 62 bytes will be carried here.
     * Hence, we overwrite the length of |adv_data| as 62 and stop parsing
     * |adv_data| if the length of |adv_data| exceeds the maximum size.
     * See bug 1190751 for detailed information.
     */
    while (adv_data[len]) {
      if (len + adv_data[len] > MAX_ADV_DATA_LEN) {
        len = MAX_ADV_DATA_LEN;
        break;
      }
      len += adv_data[len];
    }
    if (len > USHRT_MAX) {
      ALOGE("data too long");
      return;
    }
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
opcode_client_register(const struct pdu* cmd)
{
  bt_uuid_t uuid;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->register_client);

  if (read_bt_uuid_t(cmd, 0, &uuid) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->register_client(&uuid);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_register_client;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_register_client:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_unregister(const struct pdu* cmd)
{
  int32_t client_if;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->unregister_client);

  if (read_pdu_at(cmd, 0, "i", &client_if) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->unregister_client(client_if);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_unregister_client;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_unregister_client:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_scan(const struct pdu* cmd)
{
  int32_t client_if;
  uint8_t start;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->scan);

  if (read_pdu_at(cmd, 0, "iC", &client_if, &start) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
#if ANDROID_VERSION >= 21
  status = btgatt_interface->client->scan(start);
#else
  status = btgatt_interface->client->scan(client_if, start);
#endif
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_scan;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_scan:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_connect_device(const struct pdu* cmd)
{
#if ANDROID_VERSION >= 21
  long off;
  int32_t client_if, transport;
  bt_bdaddr_t bdaddr;
  uint8_t is_direct;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->connect);

  off = read_pdu_at(cmd, 0, "i", &client_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_bdaddr_t(cmd, off, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "Ci", &is_direct, &transport) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->connect(client_if, &bdaddr,
                                             is_direct, transport);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_connect_device;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_connect_device:
  cleanup_pdu_wbuf(wbuf);
  return status;
#else
  long off;
  int32_t client_if;
  bt_bdaddr_t bdaddr;
  uint8_t is_direct;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->connect);

  off = read_pdu_at(cmd, 0, "i", &client_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_bdaddr_t(cmd, off, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "C", &is_direct) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->connect(client_if, &bdaddr, is_direct);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_connect;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_connect:
  cleanup_pdu_wbuf(wbuf);
  return status;
#endif
}

static bt_status_t
opcode_client_disconnect_device(const struct pdu* cmd)
{
  long off;
  int32_t client_if, connid;
  bt_bdaddr_t bdaddr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->disconnect);

  off = read_pdu_at(cmd, 0, "i", &client_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_bdaddr_t(cmd, off, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "i", &connid) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->disconnect(client_if, &bdaddr, connid);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_disconnect;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_disconnect:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_listen(const struct pdu* cmd)
{
  int32_t client_if;
  uint8_t start;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->listen);

  if (read_pdu_at(cmd, 0, "iC", &client_if, &start) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->listen(client_if, start);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_listen;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_listen:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_refresh(const struct pdu* cmd)
{
  long off;
  int32_t client_if;
  bt_bdaddr_t bdaddr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->refresh);

  off = read_pdu_at(cmd, 0, "i", &client_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_bt_bdaddr_t(cmd, off, &bdaddr) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->refresh(client_if, &bdaddr);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_refresh;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_refresh:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_search_service(const struct pdu* cmd)
{
  long off;
  int32_t connid;
  uint8_t filtered;
  bt_uuid_t uuid;
  bt_uuid_t* uuid_p;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->search_service);

  off = read_pdu_at(cmd, 0, "iC", &connid, &filtered);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (filtered) {
    if (read_bt_uuid_t(cmd, off, &uuid) < 0) {
      return BT_STATUS_PARM_INVALID;
    }
    uuid_p = &uuid;
  } else {
    uuid_p = NULL;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->search_service(connid, uuid_p);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_search_service;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_search_service:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_get_included_service(const struct pdu* cmd)
{
  long off;
  int32_t connid;
  btgatt_srvc_id_t srvc_id;
  uint8_t continuation;
  btgatt_srvc_id_t incl_srvc_id;
  btgatt_srvc_id_t* incl_srvc_id_p;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->get_included_service);

  off = read_pdu_at(cmd, 0, "i", &connid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "C", &continuation);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (continuation) {
    off = read_btgatt_srvc_id_t(cmd, off, &incl_srvc_id);
    if (off < 0) {
      return BT_STATUS_PARM_INVALID;
    }
    incl_srvc_id_p = &incl_srvc_id;
  } else {
    incl_srvc_id_p = NULL;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->get_included_service(connid, &srvc_id,
                                                          incl_srvc_id_p);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_get_included_service;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_get_included_service:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_get_characteristic(const struct pdu* cmd)
{
  long off;
  int32_t connid;
  btgatt_srvc_id_t srvc_id;
  uint8_t continuation;
  btgatt_gatt_id_t char_id;
  btgatt_gatt_id_t* char_id_p;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->get_characteristic);

  off = read_pdu_at(cmd, 0, "i", &connid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "C", &continuation);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (continuation) {
    off = read_btgatt_gatt_id_t(cmd, off, &char_id);
    if (off < 0) {
      return BT_STATUS_PARM_INVALID;
    }
    char_id_p = &char_id;
  } else {
    char_id_p = NULL;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->get_characteristic(connid, &srvc_id,
                                                        char_id_p);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_get_characteristic;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_get_characteristic:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_get_descriptor(const struct pdu* cmd)
{
  long off;
  int32_t connid;
  btgatt_srvc_id_t srvc_id;
  btgatt_gatt_id_t char_id, desc_id;
  uint8_t continuation;
  btgatt_gatt_id_t* desc_id_p;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->get_descriptor);

  off = read_pdu_at(cmd, 0, "i", &connid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_gatt_id_t(cmd, off, &char_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "C", &continuation);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (continuation) {
    off = read_btgatt_gatt_id_t(cmd, off, &desc_id);
    if (off < 0) {
      return BT_STATUS_PARM_INVALID;
    }
    desc_id_p = &desc_id;
  } else {
    desc_id_p = NULL;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->get_descriptor(connid, &srvc_id,
                                                    &char_id, desc_id_p);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_get_descriptor;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_get_descriptor:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_read_characteristic(const struct pdu* cmd)
{
  long off;
  int32_t connid, auth_req;
  btgatt_srvc_id_t srvc_id;
  btgatt_gatt_id_t char_id;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->read_characteristic);

  off = read_pdu_at(cmd, 0, "i", &connid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_gatt_id_t(cmd, off, &char_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "i", &auth_req);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->read_characteristic(connid, &srvc_id,
                                                         &char_id, auth_req);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_read_characteristic;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_read_characteristic:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_write_characteristic(const struct pdu* cmd)
{
  long off;
  int32_t connid, write_type, len, auth_req;
  btgatt_srvc_id_t srvc_id;
  btgatt_gatt_id_t char_id;
  void* value;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->write_characteristic);

  off = read_pdu_at(cmd, 0, "i", &connid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_gatt_id_t(cmd, off, &char_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "iii", &write_type, &len, &auth_req);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (len < 0) {
    ALOGE("len is negative");
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "M", &value, (size_t)len);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }
  status = btgatt_interface->client->write_characteristic(connid, &srvc_id,
                                                          &char_id,
                                                          write_type, len,
                                                          auth_req, value);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_write_characteristic;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(value);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_write_characteristic:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  free(value);
  return status;
}

static bt_status_t
opcode_client_read_descriptor(const struct pdu* cmd)
{
  long off;
  int32_t connid;
  btgatt_srvc_id_t srvc_id;
  btgatt_gatt_id_t char_id, desc_id;
  int32_t auth_req;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->read_descriptor);

  off = read_pdu_at(cmd, 0, "i", &connid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_gatt_id_t(cmd, off, &char_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_gatt_id_t(cmd, off, &desc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "i", &auth_req);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->read_descriptor(connid, &srvc_id,
                                                     &char_id, &desc_id,
                                                     auth_req);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_read_descriptor;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_read_descriptor:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_write_descriptor(const struct pdu* cmd)
{
  long off;
  int32_t connid, write_type, len, auth_req;
  btgatt_srvc_id_t srvc_id;
  btgatt_gatt_id_t char_id, desc_id;
  void* value;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->write_descriptor);

  off = read_pdu_at(cmd, 0, "i", &connid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_gatt_id_t(cmd, off, &char_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_gatt_id_t(cmd, off, &desc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "iii", &write_type, &len, &auth_req);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (len < 0) {
    ALOGE("len is negative");
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "M", &value, (size_t)len);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }
  status = btgatt_interface->client->write_descriptor(connid, &srvc_id,
                                                      &char_id, &desc_id,
                                                      write_type, len,
                                                      auth_req, value);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_write_descriptor;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(value);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_write_descriptor:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  free(value);
  return status;
}

static bt_status_t
opcode_client_execute_write(const struct pdu* cmd)
{
  int32_t connid, execute;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->execute_write);

  if (read_pdu_at(cmd, 0, "ii", &connid, &execute) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->execute_write(connid, execute);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_execute_write;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_execute_write:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_register_for_notification(const struct pdu* cmd)
{
  long off;
  int32_t client_if;
  bt_bdaddr_t bdaddr;
  btgatt_srvc_id_t srvc_id;
  btgatt_gatt_id_t char_id;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->register_for_notification);

  off = read_pdu_at(cmd, 0, "i", &client_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_bdaddr_t(cmd, off, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_gatt_id_t(cmd, off, &char_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->register_for_notification(client_if,
                                                               &bdaddr,
                                                               &srvc_id,
                                                               &char_id);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_register_for_notification;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_register_for_notification:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_deregister_for_notification(const struct pdu* cmd)
{
  long off;
  int32_t client_if;
  bt_bdaddr_t bdaddr;
  btgatt_srvc_id_t srvc_id;
  btgatt_gatt_id_t char_id;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->deregister_for_notification);

  off = read_pdu_at(cmd, 0, "i", &client_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_bdaddr_t(cmd, off, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_gatt_id_t(cmd, off, &char_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->deregister_for_notification(client_if,
                                                                 &bdaddr,
                                                                 &srvc_id,
                                                                 &char_id);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_deregister_for_notification;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_deregister_for_notification:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_read_remote_rssi(const struct pdu* cmd)
{
  long off;
  int32_t client_if;
  bt_bdaddr_t bdaddr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->read_remote_rssi);

  off = read_pdu_at(cmd, 0, "i", &client_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_bt_bdaddr_t(cmd, off, &bdaddr) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->read_remote_rssi(client_if, &bdaddr);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_read_remote_rssi;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_read_remote_rssi:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_get_device_type(const struct pdu* cmd)
{
  int type;
  bt_bdaddr_t bdaddr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->get_device_type);

  if (read_bt_bdaddr_t(cmd, 0, &bdaddr) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(1, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  type = btgatt_interface->client->get_device_type(&bdaddr);
  if (type > (int)UCHAR_MAX) {
    ALOGE("type too large");
    status = BT_STATUS_FAIL;
    goto err_btgatt_interface_client_get_device_type;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  if (append_to_pdu(&wbuf->buf.pdu, "C", type) < 0) {
    status = BT_STATUS_FAIL;
    goto err_append_to_pdu_at;
  }
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_append_to_pdu_at:
err_btgatt_interface_client_get_device_type:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_set_advertising_data(const struct pdu* cmd)
{
  long off;
  int32_t server_if, min_ival, max_ival, appearence;
  uint8_t set_scan_rsp, include_name, include_txpower;
  uint16_t manu_len, data_len, uuid_len;
  void* manu;
  void* data;
  void* uuid;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->set_adv_data);

  off = read_pdu_at(cmd, 0, "iCCCiiiSSS", &server_if,
                                          &set_scan_rsp,
                                          &include_name,
                                          &include_txpower,
                                          &min_ival,
                                          &max_ival,
                                          &appearence,
                                          &manu_len,
                                          &data_len,
                                          &uuid_len);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "M", &manu, (size_t)manu_len) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "M", &data, (size_t)data_len) < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at_data;
  }
  if (read_pdu_at(cmd, off, "M", &uuid, (size_t)uuid_len) < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at_uuid;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }
#if ANDROID_VERSION_CONST >= ENCODED_ANDROID_VERSION_CONST(4,4,3)
  status = btgatt_interface->client->set_adv_data(server_if, set_scan_rsp,
                                                  include_name,
                                                  include_txpower,
                                                  min_ival, max_ival,
                                                  appearence,
                                                  manu_len, manu,
                                                  data_len, data,
                                                  uuid_len, uuid);
#else
  status = btgatt_interface->client->set_adv_data(server_if, set_scan_rsp,
                                                  include_name,
                                                  include_txpower,
                                                  min_ival, max_ival,
                                                  appearence,
                                                  manu_len, manu);
#endif
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_set_adv_data;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(uuid);
  free(data);
  free(manu);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_set_adv_data:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  free(uuid);
err_read_pdu_at_uuid:
  free(data);
err_read_pdu_at_data:
  free(manu);
  return status;
}

static bt_status_t
opcode_client_test_command(const struct pdu* cmd)
{
  long off;
  int32_t command;
  btgatt_test_params_t params;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->test_command);

  off = read_pdu_at(cmd, 0, "i", &command);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_btgatt_test_params_t(cmd, off, &params) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }
  status = btgatt_interface->client->test_command(command, &params);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_test_command;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  cleanup_btgatt_test_params_t(&params);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_test_command:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  cleanup_btgatt_test_params_t(&params);
  return status;
}

#if ANDROID_VERSION >= 21
static bt_status_t
opcode_client_scan_filter_param_setup(const struct pdu* cmd)
{
  long off;
  int32_t client_if, action, filt_index, feat_seln, list_logic_type,
          filt_logic_type, rssi_high_thres, rssi_low_thres, dely_mode,
          found_timeout, lost_timeout, found_timeout_cnt;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->scan_filter_param_setup);

  off = read_pdu_at(cmd, 0, "iiiiiiiiiiii", &client_if,
                                            &action,
                                            &filt_index,
                                            &feat_seln,
                                            &list_logic_type,
                                            &filt_logic_type,
                                            &rssi_high_thres,
                                            &rssi_low_thres,
                                            &dely_mode,
                                            &found_timeout,
                                            &lost_timeout,
                                            &found_timeout_cnt);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->scan_filter_param_setup(client_if,
                                                             action,
                                                             filt_index,
                                                             feat_seln,
                                                             list_logic_type,
                                                             filt_logic_type,
                                                             rssi_high_thres,
                                                             rssi_low_thres,
                                                             dely_mode,
                                                             found_timeout,
                                                             lost_timeout,
                                                             found_timeout_cnt);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_scan_filter_param_setup;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_scan_filter_param_setup:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_scan_filter_add_remove(const struct pdu* cmd)
{
  long off;
  int32_t client_if, action, filt_type, filt_index, company_id,
          company_id_mask, data_len, mask_len;
  bt_uuid_t uuid;
  bt_uuid_t uuid_mask;
  bt_bdaddr_t bdaddr;
  uint8_t addr_type;
  void* data;
  void* mask;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->scan_filter_param_setup);

  off = read_pdu_at(cmd, 0, "iiiiii", &client_if,
                                      &action,
                                      &filt_type,
                                      &filt_index,
                                      &company_id,
                                      &company_id_mask);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off= read_bt_uuid_t(cmd, off, &uuid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off= read_bt_uuid_t(cmd, off, &uuid_mask);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off= read_bt_bdaddr_t(cmd, off, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, 0, "Cii", &addr_type, &data_len, &mask_len);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (data_len < 0) {
    ALOGE("data_len is negative");
    return BT_STATUS_PARM_INVALID;
  }
  if (mask_len < 0) {
    ALOGE("mask_len is negative");
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, 0, "M", &data, (size_t)data_len);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, 0, "M", &mask, (size_t)mask_len);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at_mask;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }
  status = btgatt_interface->client->scan_filter_add_remove(client_if,
                                                            action,
                                                            filt_type,
                                                            filt_index,
                                                            company_id,
                                                            company_id_mask,
                                                            &uuid,
                                                            &uuid_mask,
                                                            &bdaddr,
                                                            (char)addr_type,
                                                            data_len, data,
                                                            mask_len, mask);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_scan_filter_add_remove;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(mask);
  free(data);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_scan_filter_add_remove:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  free(mask);
err_read_pdu_at_mask:
  free(data);
  return status;
}

static bt_status_t
opcode_client_scan_filter_clear(const struct pdu* cmd)
{
  int32_t client_if, filt_index;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->scan_filter_clear);

  if (read_pdu_at(cmd, 0, "ii", &client_if, &filt_index) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->scan_filter_clear(client_if,
                                                       filt_index);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_scan_filter_clear;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_scan_filter_clear:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_scan_filter_enable(const struct pdu* cmd)
{
  int32_t client_if;
  uint8_t enable;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->scan_filter_enable);

  if (read_pdu_at(cmd, 0, "iC", &client_if, &enable) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->scan_filter_enable(client_if,
                                                        enable);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_scan_filter_enable;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_scan_filter_enable:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_configure_mtu(const struct pdu* cmd)
{
  int32_t connid, mtu;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->configure_mtu);

  if (read_pdu_at(cmd, 0, "ii", &connid, &mtu) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->configure_mtu(connid, mtu);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_configure_mtu;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_configure_mtu:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_conn_parameter_update(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bdaddr;
  int32_t min_ival, max_ival, latency, timeout;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->conn_parameter_update);

  off= read_bt_bdaddr_t(cmd, 0, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, 0, "iiii", &min_ival,
                                    &max_ival,
                                    &latency,
                                    &timeout);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->conn_parameter_update(&bdaddr,
                                                           min_ival,
                                                           max_ival,
                                                           latency,
                                                           timeout);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_conn_parameter_update;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_conn_parameter_update:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_set_scan_parameters(const struct pdu* cmd)
{
  int32_t interval, window;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->set_scan_parameters);

  if (read_pdu_at(cmd, 0, "ii", &interval, &window) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->set_scan_parameters(interval, window);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_set_scan_parameters;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_set_scan_parameters:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_multi_adv_enable(const struct pdu* cmd)
{
  long off;
  int32_t client_if, min_ival, max_ival, adv_type, channel_map, txpower,
          timeout;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->multi_adv_enable);

  off = read_pdu_at(cmd, 0, "iiiiiii", &client_if,
                                       &min_ival,
                                       &max_ival,
                                       &adv_type,
                                       &channel_map,
                                       &txpower,
                                       &timeout);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->multi_adv_enable(client_if, min_ival,
                                                      max_ival, adv_type,
                                                      channel_map, txpower,
                                                      timeout);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_multi_adv_enable;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_multi_adv_enable:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_multi_adv_update(const struct pdu* cmd)
{
  long off;
  int32_t client_if, min_ival, max_ival, adv_type, channel_map, txpower,
          timeout;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->multi_adv_update);

  off = read_pdu_at(cmd, 0, "iiiiiii", &client_if,
                                       &min_ival,
                                       &max_ival,
                                       &adv_type,
                                       &channel_map,
                                       &txpower,
                                       &timeout);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->multi_adv_update(client_if, min_ival,
                                                      max_ival, adv_type,
                                                      channel_map, txpower,
                                                      timeout);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_multi_adv_update;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_multi_adv_update:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_multi_adv_set_inst_data(const struct pdu* cmd)
{
  long off;
  int32_t client_if, appearence, manu_len, data_len, uuid_len;
  uint8_t set_scan_rsp, include_name, include_txpower;
  void* manu;
  void* data;
  void* uuid;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->multi_adv_set_inst_data);

  off = read_pdu_at(cmd, 0, "iCCCiiii", &client_if,
                                        &set_scan_rsp,
                                        &include_name,
                                        &include_txpower,
                                        &appearence,
                                        &manu_len,
                                        &data_len,
                                        &uuid_len);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (manu_len < 0) {
    ALOGE("manu_len is negative");
    return BT_STATUS_PARM_INVALID;
  }
  if (data_len < 0) {
    ALOGE("data_len is negative");
    return BT_STATUS_PARM_INVALID;
  }
  if (uuid_len < 0) {
    ALOGE("uuid_len is negative");
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "M", &manu, (size_t)manu_len);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "M", &data, (size_t)data_len);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at_data;
  }
  off = read_pdu_at(cmd, off, "M", &uuid, (size_t)uuid_len);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_pdu_at_uuid;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }
  status = btgatt_interface->client->multi_adv_set_inst_data(client_if,
                                                             set_scan_rsp,
                                                             include_name,
                                                             include_txpower,
                                                             appearence,
                                                             manu_len, manu,
                                                             data_len, data,
                                                             uuid_len, uuid);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_multi_adv_update;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(uuid);
  free(data);
  free(manu);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_multi_adv_update:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  free(uuid);
err_read_pdu_at_uuid:
  free(data);
err_read_pdu_at_data:
  free(manu);
  return status;
}

static bt_status_t
opcode_client_multi_adv_disable(const struct pdu* cmd)
{
  long off;
  int32_t client_if;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->multi_adv_disable);

  off = read_pdu_at(cmd, 0, "i", &client_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->multi_adv_disable(client_if);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_multi_adv_disable;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_multi_adv_disable:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_batchscan_cfg_storage(const struct pdu* cmd)
{
  long off;
  int32_t client_if, full_max, trunc_max, notify_threshold;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->batchscan_cfg_storage);

  off = read_pdu_at(cmd, 0, "iiii", &client_if,
                                    &full_max,
                                    &trunc_max,
                                    &notify_threshold);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->batchscan_cfg_storage(client_if,
                                                           full_max,
                                                           trunc_max,
                                                           notify_threshold);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_batchscan_cfg_storage;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_batchscan_cfg_storage:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_batchscan_enb_batch_scan(const struct pdu* cmd)
{
  long off;
  int32_t client_if, scan_mode, scan_ival, scan_window, addr_type, discard;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->batchscan_enb_batch_scan);

  off = read_pdu_at(cmd, 0, "iiiiii", &client_if,
                                      &scan_mode,
                                      &scan_ival,
                                      &scan_window,
                                      &addr_type,
                                      &discard);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->batchscan_enb_batch_scan(client_if,
                                                              scan_mode,
                                                              scan_ival,
                                                              scan_window,
                                                              addr_type,
                                                              discard);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_batchscan_enb_batch_scan;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_batchscan_enb_batch_scan:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_batchscan_dis_batch_scan(const struct pdu* cmd)
{
  int32_t client_if;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->batchscan_dis_batch_scan);

  if (read_pdu_at(cmd, 0, "i", &client_if) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->batchscan_dis_batch_scan(client_if);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_batchscan_dis_batch_scan;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_batchscan_dis_batch_scan:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_client_batchscan_read_reports(const struct pdu* cmd)
{
  long off;
  int32_t client_if, scan_mode;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->client);
  assert(btgatt_interface->client->batchscan_read_reports);

  if (read_pdu_at(cmd, 0, "ii", &client_if, &scan_mode) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->client->batchscan_read_reports(client_if,
                                                            scan_mode);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_client_batchscan_read_reports;
  }

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_client_batchscan_read_reports:
  cleanup_pdu_wbuf(wbuf);
  return status;
}
#endif

static bt_status_t
opcode_server_register(const struct pdu* cmd)
{
  bt_uuid_t uuid;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->register_server);

  if (read_bt_uuid_t(cmd, 0, &uuid) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->register_server(&uuid);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_register_server;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_register_server:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_unregister(const struct pdu* cmd)
{
  int32_t server_if;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->unregister_server);

  if (read_pdu_at(cmd, 0, "i", &server_if) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->unregister_server(server_if);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_unregister_server;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_unregister_server:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_connect(const struct pdu* cmd)
{
#if ANDROID_VERSION >= 21
  long off;
  int32_t server_if, transport;
  bt_bdaddr_t bdaddr;
  uint8_t is_direct;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->connect);

  off = read_pdu_at(cmd, 0, "i", &server_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_bdaddr_t(cmd, off, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "Ci", &is_direct, &transport) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->connect(server_if, &bdaddr,
                                             is_direct, transport);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_connect;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_connect:
  cleanup_pdu_wbuf(wbuf);
  return status;
#else
  long off;
  int32_t server_if;
  bt_bdaddr_t bdaddr;
  uint8_t is_direct;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->connect);

  off = read_pdu_at(cmd, 0, "i", &server_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_bdaddr_t(cmd, off, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "C", &is_direct) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->connect(server_if, &bdaddr, is_direct);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_connect;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_connect:
  cleanup_pdu_wbuf(wbuf);
  return status;
#endif
}

static bt_status_t
opcode_server_disconnect(const struct pdu* cmd)
{
  long off;
  int32_t server_if, connid;
  bt_bdaddr_t bdaddr;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->disconnect);

  off = read_pdu_at(cmd, 0, "i", &server_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_bdaddr_t(cmd, off, &bdaddr);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "i", &connid) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->disconnect(server_if, &bdaddr, connid);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_disconnect;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_disconnect:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_add_service(const struct pdu* cmd)
{
  long off;
  int32_t server_if, num_handles;
  btgatt_srvc_id_t srvc_id;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->add_service);

  off = read_pdu_at(cmd, 0, "i", &server_if);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_btgatt_srvc_id_t(cmd, off, &srvc_id);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "i", &num_handles) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->add_service(server_if, &srvc_id,
                                                 num_handles);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_add_service;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_add_service:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_add_included_service(const struct pdu* cmd)
{
  long off;
  int32_t server_if, service_handle, included_handle;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->add_included_service);

  off = read_pdu_at(cmd, 0, "iii", &server_if,
                                   &service_handle,
                                   &included_handle);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->add_included_service(server_if,
                                                          service_handle,
                                                          included_handle);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_add_included_service;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_add_included_service:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_add_characteristic(const struct pdu* cmd)
{
  long off;
  int32_t server_if, service_handle, properties, permissions;
  bt_uuid_t uuid;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->add_characteristic);

  off = read_pdu_at(cmd, 0, "ii", &server_if, &service_handle);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_uuid_t(cmd, off, &uuid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "ii", &properties, &permissions);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->add_characteristic(server_if,
                                                        service_handle,
                                                        &uuid, properties,
                                                        permissions);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_add_characteristic;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_add_characteristic:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_add_descriptor(const struct pdu* cmd)
{
  long off;
  int32_t server_if, service_handle, permissions;
  bt_uuid_t uuid;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->add_descriptor);

  off = read_pdu_at(cmd, 0, "ii", &server_if, &service_handle);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_bt_uuid_t(cmd, off, &uuid);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "i", &permissions);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->add_descriptor(server_if, service_handle,
                                                    &uuid, permissions);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_add_descriptor;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_add_descriptor:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_start_service(const struct pdu* cmd)
{
  long off;
  int32_t server_if, service_handle, transport;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->start_service);

  off = read_pdu_at(cmd, 0, "iii", &server_if,
                                   &service_handle,
                                   &transport);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->start_service(server_if, service_handle,
                                                   transport);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_start_service;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_start_service:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_stop_service(const struct pdu* cmd)
{
  int32_t server_if, service_handle;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->stop_service);

  if (read_pdu_at(cmd, 0, "ii", &server_if, &service_handle) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->stop_service(server_if, service_handle);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_stop_service;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_stop_service:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_delete_service(const struct pdu* cmd)
{
  int32_t server_if, service_handle;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->delete_service);

  if (read_pdu_at(cmd, 0, "ii", &server_if, &service_handle) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    return BT_STATUS_NOMEM;
  }
  status = btgatt_interface->server->delete_service(server_if, service_handle);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_delete_service;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_delete_service:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_server_send_indication(const struct pdu* cmd)
{
  long off;
  int32_t server_if, attrib_handle, connid, len, confirm;
  void* value;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->send_indication);

  off = read_pdu_at(cmd, 0, "iiiii", &server_if,
                                     &attrib_handle,
                                     &connid,
                                     &len,
                                     &confirm);
  if (off < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  if (len < 0) {
    ALOGE("len is negative");
    return BT_STATUS_PARM_INVALID;
  }
  if (read_pdu_at(cmd, off, "M", &value, (size_t)len) < 0) {
    return BT_STATUS_PARM_INVALID;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }
  status = btgatt_interface->server->send_indication(server_if,
                                                     attrib_handle, connid,
                                                     len, confirm, value);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_send_indication;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(value);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_send_indication:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  free(value);
  return status;
}

static bt_status_t
opcode_server_send_response(const struct pdu* cmd)
{
  long off;
  int32_t connid, transid, stat;
  btgatt_response_t response;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btgatt_interface);
  assert(btgatt_interface->server);
  assert(btgatt_interface->server->send_response);

  /* The HAL protocol mixes up |response| and |stat|. Thus
   * we have to read the values directly without a helper
   * function.
   */
  off = read_pdu_at(cmd, 0, "iiSSCiS", &connid,
                                       &transid,
                                       &response.attr_value.handle,
                                       &response.attr_value.offset,
                                       &response.attr_value.auth_req,
                                       &stat,
                                       &response.attr_value.len);
  if (off < 0) {
    return -1;
  }
  if (response.attr_value.len > BTGATT_MAX_ATTR_LEN) {
    ALOGE("len is too large");
    return BT_STATUS_PARM_INVALID;
  }
  off = read_pdu_at(cmd, off, "m", response.attr_value.value,
                                   (size_t)response.attr_value.len);
  if (off < 0) {
    return -1;
  }
  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }
  status = btgatt_interface->server->send_response(connid, transid, stat,
                                                   &response);
  if (status != BT_STATUS_SUCCESS) {
    goto err_btgatt_interface_server_send_response;
  }
  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btgatt_interface_server_send_response:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  return status;
}

static bt_status_t
bt_gatt_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
    [OPCODE_CLIENT_REGISTER] = opcode_client_register,
    [OPCODE_CLIENT_UNREGISTER] = opcode_client_unregister,
    [OPCODE_CLIENT_SCAN] = opcode_client_scan,
    [OPCODE_CLIENT_CONNECT_DEVICE] = opcode_client_connect_device,
    [OPCODE_CLIENT_DISCONNECT_DEVICE] = opcode_client_disconnect_device,
    [OPCODE_CLIENT_LISTEN] = opcode_client_listen,
    [OPCODE_CLIENT_REFRESH] = opcode_client_refresh,
    [OPCODE_CLIENT_SEARCH_SERVICE]= opcode_client_search_service,
    [OPCODE_CLIENT_GET_INCLUDED_SERVICES] =
      opcode_client_get_included_service,
    [OPCODE_CLIENT_GET_CHARACTERISTIC] =  opcode_client_get_characteristic,
    [OPCODE_CLIENT_GET_DESCRIPTOR] = opcode_client_get_descriptor,
    [OPCODE_CLIENT_READ_CHARACTERISTIC] = opcode_client_read_characteristic,
    [OPCODE_CLIENT_WRITE_CHARACTERISTIC] = opcode_client_write_characteristic,
    [OPCODE_CLIENT_READ_DESCRIPTOR] = opcode_client_read_descriptor,
    [OPCODE_CLIENT_WRITE_DESCRIPTOR] = opcode_client_write_descriptor,
    [OPCODE_CLIENT_EXECUTE_WRITE] = opcode_client_execute_write,
    [OPCODE_CLIENT_REGISTER_FOR_NOTIFICATION] =
      opcode_client_register_for_notification,
    [OPCODE_CLIENT_DEREGISTER_FOR_NOTIFICATION] =
      opcode_client_deregister_for_notification,
    [OPCODE_CLIENT_READ_REMOTE_RSSI] = opcode_client_read_remote_rssi,
    [OPCODE_CLIENT_GET_DEVICE_TYPE] = opcode_client_get_device_type,
    [OPCODE_CLIENT_SET_ADVERTISING_DATA] = opcode_client_set_advertising_data,
    [OPCODE_CLIENT_TEST_COMMAND] = opcode_client_test_command,
    [OPCODE_SERVER_REGISTER_COMMAND] = opcode_server_register,
    [OPCODE_SERVER_UNREGISTER_COMMAND] = opcode_server_unregister,
    [OPCODE_SERVER_CONNECT_PERIPHERIAL] = opcode_server_connect,
    [OPCODE_SERVER_DISCONNECT_PERIPHERIAL] = opcode_server_disconnect,
    [OPCODE_SERVER_ADD_SERVICE] = opcode_server_add_service,
    [OPCODE_SERVER_ADD_INCLUDED_SERVICE] = opcode_server_add_included_service,
    [OPCODE_SERVER_ADD_CHARACTERISTIC] = opcode_server_add_characteristic,
    [OPCODE_SERVER_ADD_DESCRIPTOR] = opcode_server_add_descriptor,
    [OPCODE_SERVER_START_SERVICE] = opcode_server_start_service,
    [OPCODE_SERVER_STOP_SERVICE] = opcode_server_stop_service,
    [OPCODE_SERVER_DELETE_SERVICE] = opcode_server_delete_service,
    [OPCODE_SERVER_SEND_INDICATION] = opcode_server_send_indication,
    [OPCODE_SERVER_SEND_RESPONSE] = opcode_server_send_response,
#if ANDROID_VERSION >= 21
    [OPCODE_CLIENT_SCAN_FILTER_PARAMS_SETUP] =
      opcode_client_scan_filter_param_setup,
    [OPCODE_CLIENT_SCAN_FILTER_ADD_REMOVE] =
      opcode_client_scan_filter_add_remove,
    [OPCODE_CLIENT_SCAN_FILTER_CLEAR] = opcode_client_scan_filter_clear,
    [OPCODE_CLIENT_SCAN_FILTER_ENABLE] = opcode_client_scan_filter_enable,
    [OPCODE_CLIENT_CONFIGURE_MTU] = opcode_client_configure_mtu,
    [OPCODE_CLIENT_CONNECTION_PARAMETER_UPDATE] =
      opcode_client_conn_parameter_update,
    [OPCODE_CLIENT_SET_SCAN_PARAMETERS] = opcode_client_set_scan_parameters,
    [OPCODE_CLIENT_SETUP_MULTI_ADVERTISING] = opcode_client_multi_adv_enable,
    [OPCODE_CLIENT_UPDATE_MULTI_ADVERTISING] = opcode_client_multi_adv_update,
    [OPCODE_CLIENT_SETUP_MULTI_ADVERTISING_INSTANCE] =
      opcode_client_multi_adv_set_inst_data,
    [OPCODE_CLIENT_DISABLE_MULTI_ADVERTISING_INSTANCE] =
      opcode_client_multi_adv_disable,
    [OPCODE_CLIENT_CONFIGURE_BATCHSCAN] = opcode_client_batchscan_cfg_storage,
    [OPCODE_CLIENT_ENABLE_BATCHSCAN] = opcode_client_batchscan_enb_batch_scan,
    [OPCODE_CLIENT_DISABLE_BATCHSCAN] = opcode_client_batchscan_dis_batch_scan,
    [OPCODE_CLIENT_READ_BATCHSCAN_REPORTS] =
      opcode_client_batchscan_read_reports
#endif
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
