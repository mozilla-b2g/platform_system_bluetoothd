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

/*
 * Protocol helpers
 */

/*
 * Notifications
 */

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
  static btgatt_client_callbacks_t btgatt_client_callbacks;

  static btgatt_server_callbacks_t btgatt_server_callbacks;

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
