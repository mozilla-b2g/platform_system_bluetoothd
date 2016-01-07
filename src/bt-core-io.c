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
#include <fdio/task.h>
#include <fdio/timer.h>
#include <hardware/bluetooth.h>
#include <hardware_legacy/power.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/queue.h>
#include "bt-proto.h"
#include "bt-pdubuf.h"
#include "bt-core-io.h"
#include "compiler.h"
#include "log.h"
#include "sdpsrvc.h"

enum {
  /* commands/responses */
  OPCODE_ENABLE = 0x01,
  OPCODE_DISABLE = 0x02,
  OPCODE_GET_ADAPTER_PROPERTIES = 0x03,
  OPCODE_GET_ADAPTER_PROPERTY = 0x04,
  OPCODE_SET_ADAPTER_PROPERTY = 0x05,
  OPCODE_GET_REMOTE_DEVICE_PROPERTIES = 0x06,
  OPCODE_GET_REMOTE_DEVICE_PROPERTY = 0x07,
  OPCODE_SET_REMOTE_DEVICE_PROPERTY = 0x08,
  OPCODE_GET_REMOTE_SERVICE_RECORD = 0x09,
  OPCODE_GET_REMOTE_SERVICES = 0x0a,
  OPCODE_START_DISCOVERY = 0x0b,
  OPCODE_CANCEL_DISCOVERY = 0x0c,
  OPCODE_CREATE_BOND = 0x0d,
  OPCODE_REMOVE_BOND = 0x0e,
  OPCODE_CANCEL_BOND = 0x0f,
  OPCODE_PIN_REPLY = 0x10,
  OPCODE_SSP_REPLY = 0x11,
  OPCODE_DUT_MODE_CONFIGURE = 0x12,
  OPCODE_DUT_MODE_SEND = 0x13,
#if ANDROID_VERSION >= 18
  OPCODE_LE_TEST_MODE = 0x14,
#endif
  /* notifications */
  OPCODE_ADAPTER_STATE_CHANGED_NTF = 0x81,
  OPCODE_ADAPTER_PROPERTIES_CHANGED_NTF = 0x82,
  OPCODE_REMOTE_DEVICE_PROPERTIES_NTF = 0x83,
  OPCODE_DEVICE_FOUND_NTF = 0x84,
  OPCODE_DISCOVERY_STATE_CHANGED_NTF = 0x85,
  OPCODE_PIN_REQUEST_NTF = 0x86,
  OPCODE_SSP_REQUEST_NTF = 0x87,
  OPCODE_BOND_STATE_CHANGED_NTF = 0x88,
  OPCODE_ACL_STATE_CHANGED_NTF = 0x89,
  OPCODE_DUT_MODE_RECEIVE_NTF = 0x8a,
  OPCODE_LE_TEST_MODE_NTF = 0x8b
};

#define ARRAY_LENGTH(_array) \
  ( sizeof(_array) / sizeof((_array)[0]) )

static void (*send_pdu)(struct pdu_wbuf* wbuf);
static bluetooth_device_t*   bt_device;
static const bt_interface_t* bt_interface;

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
 * Bug 1142007: The function |get_remote_service_record| does not return a
 * useful result in its callback. Thus we have to work around the problem.
 *
 * Before calling |get_remote_service_record|, we store its parameters in
 * a queue. After having receiving the service record, we copy the stored
 * UUID into the result structure. Gecko will then be able to match call
 * and result.
 */

struct get_remote_service_record_params {
  TAILQ_ENTRY(get_remote_service_record_params) q;
  bt_bdaddr_t bdaddr;
  bt_uuid_t uuid;
};

TAILQ_HEAD(get_remote_service_record_q_head,
           get_remote_service_record_params);

struct get_remote_service_record_q {
  pthread_mutex_t lock;
  struct get_remote_service_record_q_head head;
};

#define GET_REMOTE_SERVICE_RECORD_Q_INITIALIZER(_q) \
  { \
    .lock = PTHREAD_MUTEX_INITIALIZER, \
    .head = TAILQ_HEAD_INITIALIZER((_q).head) \
  }

static struct get_remote_service_record_q get_remote_service_record_q =
  GET_REMOTE_SERVICE_RECORD_Q_INITIALIZER(get_remote_service_record_q);

static struct get_remote_service_record_params*
alloc_get_remote_service_record_params(void)
{
  struct get_remote_service_record_params* params;

  params = malloc(sizeof(*params));
  if (!params){
    ALOGE_ERRNO("malloc");
    return NULL;
  }
  return params;
}

static void
free_get_remote_service_record_params(
  struct get_remote_service_record_params* params)
{
  free(params);
}

static struct get_remote_service_record_params*
store_get_remote_service_record_params(const bt_bdaddr_t* bdaddr,
                                       const bt_uuid_t* uuid)
{
  struct get_remote_service_record_params* params;
  int err;

  assert(bdaddr);
  assert(uuid);

  params = alloc_get_remote_service_record_params();
  if (!params){
    return NULL;
  }
  memcpy(&params->bdaddr, bdaddr, sizeof(params->bdaddr));
  memcpy(&params->uuid, uuid, sizeof(params->uuid));

  err = pthread_mutex_lock(&get_remote_service_record_q.lock);
  if (err) {
    ALOGE_ERRNO_NO("pthread_mutex_lock", err);
    free_get_remote_service_record_params(params);
    return NULL;
  }

  TAILQ_INSERT_TAIL(&get_remote_service_record_q.head, params, q);

  err = pthread_mutex_unlock(&get_remote_service_record_q.lock);
  if (err) {
    ALOGW_ERRNO_NO("pthread_mutex_unlock", err);
  }

  return params;
}

static struct get_remote_service_record_params*
fetch_get_remote_service_record_params(const bt_bdaddr_t* bdaddr)
{
  int err;
  struct get_remote_service_record_params* params;

  assert(bdaddr);

  err = pthread_mutex_lock(&get_remote_service_record_q.lock);
  if (err) {
    ALOGE_ERRNO_NO("pthread_mutex_lock", err);
    return NULL;
  }

  params = TAILQ_FIRST(&get_remote_service_record_q.head);

  while (params) {
    if (!memcmp(&params->bdaddr, bdaddr, sizeof(params->bdaddr))) {
      break;
    }
    params = TAILQ_NEXT(params, q);
  }

  if (params) {
    TAILQ_REMOVE(&get_remote_service_record_q.head, params, q);
  }

  err = pthread_mutex_unlock(&get_remote_service_record_q.lock);
  if (err) {
    ALOGW_ERRNO_NO("pthread_mutex_unlock", err);
  }

  return params;
}

static void
remove_get_remote_service_record_params(
  struct get_remote_service_record_params* params)
{
  int err;

  assert(params);

  err = pthread_mutex_lock(&get_remote_service_record_q.lock);
  if (err) {
    ALOGE_ERRNO_NO("pthread_mutex_lock", err);
    /* We'll be leaking |params| here, but that's probably better
     * than accessing the parameter queue in an unsyncronized way.
     */
    return;
  }

  TAILQ_REMOVE(&get_remote_service_record_q.head, params, q);

  err = pthread_mutex_unlock(&get_remote_service_record_q.lock);
  if (err) {
    ALOGW_ERRNO_NO("pthread_mutex_unlock", err);
  }

  free_get_remote_service_record_params(params);
}

/*
 * Properties handling
 */

static unsigned long
properties_length(int num_properties, const bt_property_t* properties)
{
  static const unsigned long PROPERTY_SIZE = 3; /* 3 bytes per property */

  unsigned long len;
  int i;

  for (len = PROPERTY_SIZE * num_properties, i = 0; i < num_properties; ++i) {
    len += properties[i].len;
  }
  return len;
}

static void
fix_properties(const bt_bdaddr_t* remote_addr,
               int num_properties, bt_property_t* properties)
{
  static const bt_uuid_t uuid_zero; /* filled with zeros */

  int i;

  for (i = 0; i < num_properties; ++i) {
    if (properties[i].type == BT_PROPERTY_SERVICE_RECORD) {

      /* Bug 1142007: BT_PROPERTY_SERVICE_RECORD returns
       *
       *  {
       *    .uuid = 0,
       *    .channel = SCN,
       *    .name = "\0"
       *  }
       *
       * for every remote service. We replace the UUID with
       * the one we asked for in |get_remote_service_record|.
       */

      struct get_remote_service_record_params* params;
      bt_service_record_t* rec;

      params = fetch_get_remote_service_record_params(remote_addr);
      if (!params) {
        ALOGW("no parameters for BT_PROPERTY_SERVICE_RECORD stored");
        continue; /* no params stored; send record as-is */
      }

      rec = properties[i].val;

      if (memcmp(&uuid_zero, &rec->uuid, sizeof(uuid_zero))) {
        free_get_remote_service_record_params(params);
        continue; /* record contains non-zero UUID; nothing to fix */
      }

      /* We replace the property's UUID with the one we stored
       * for |get_remote_service_record|. That will make Gecko
       * recognize the notification correctly. The channel is
       * left as it is. We can set an arbitrary string for the
       * name.
       *
       * Remote devices can create their own names for services
       * they provide. We have no way of knowing them, so we set
       * the service's name as defined by the SDP spec and use
       * "\0" for any other service. Applications can at least
       * detect this case easily and use a generic string.
       */

      memcpy(&rec->uuid, &params->uuid, sizeof(rec->uuid));
      strncpy(rec->name,
              lookup_service_name_by_uuid16(
                UUID16(rec->uuid.uu[2], rec->uuid.uu[3]), ""),
              sizeof(rec->name));
      rec->name[ARRAY_LENGTH(rec->name) - 1] = '\0'; /* always terminate */

      free_get_remote_service_record_params(params);
    }
  }
}

/*
 * Notifications
 */

static void
adapter_state_changed_cb(bt_state_t state)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1, /* state */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE, OPCODE_ADAPTER_STATE_CHANGED_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static int
is_aligned(const void* addr)
{
  return !(((const uintptr_t)addr) % sizeof(void*));
}

/* See Bug 989976: consider address in |properties| is not aligned. If
 * it is aligned, we return the pointer directly; otherwise we make
 * an aligned copy. The argument |aligned_properties| keeps track of
 * the memory buffer.
 */
static bt_property_t*
align_properties(bt_property_t* properties, size_t num_properties,
                 bt_property_t** aligned_properties)
{
  size_t siz;

  if (is_aligned(properties)) {
    *aligned_properties = NULL;
    return properties;
  }

  siz = sizeof(**aligned_properties) * num_properties;

  *aligned_properties = malloc(siz);
  if (!*aligned_properties) {
    ALOGE_ERRNO("malloc");
    return NULL;
  }
  memcpy(*aligned_properties, properties, siz);

  return *aligned_properties;
}

static void
adapter_properties_cb(bt_status_t status, int num_properties,
                      bt_property_t* properties)
{
  bt_property_t* aligned_properties;
  struct pdu_wbuf* wbuf;

  properties = align_properties(properties, num_properties,
                                &aligned_properties);
  if (!properties)
    return;

  wbuf = create_pdu_wbuf(1 + /* status */
                         1 + /* number of properties */
                         properties_length(num_properties, properties),
                         0, NULL);
  if (!wbuf)
    goto cleanup_properties;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE,
           OPCODE_ADAPTER_PROPERTIES_CHANGED_NTF);

  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)status) < 0)
    goto cleanup;

  if (append_bt_property_t_array(&wbuf->buf.pdu,
                                 properties, num_properties) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  free(aligned_properties);

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
cleanup_properties:
  free(aligned_properties);
}

static void
remote_device_properties_cb(bt_status_t status,
                            bt_bdaddr_t* bd_addr,
                            int num_properties,
                            bt_property_t* properties)
{
  bt_property_t* aligned_properties;
  struct pdu_wbuf* wbuf;

  properties = align_properties(properties, num_properties,
                                &aligned_properties);
  if (!properties)
    return;

  fix_properties(bd_addr, num_properties, properties);

  wbuf = create_pdu_wbuf(1 + /* status */
                         6 + /* address */
                         1 + /* number of properties */
                         properties_length(num_properties, properties),
                         0, NULL);
  if (!wbuf)
    goto cleanup_properties;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE,
           OPCODE_REMOTE_DEVICE_PROPERTIES_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)status) < 0)
    goto cleanup;
  if (append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0)
    goto cleanup;
  if (append_bt_property_t_array(&wbuf->buf.pdu,
                                 properties, num_properties) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  free(aligned_properties);

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
cleanup_properties:
  free(aligned_properties);
}

static void
device_found_cb(int num_properties, bt_property_t* properties)
{
  bt_property_t* aligned_properties;
  struct pdu_wbuf* wbuf;

  properties = align_properties(properties, num_properties,
                                &aligned_properties);
  if (!properties)
    return;

  wbuf = create_pdu_wbuf(1 + /* number of properties */
                         properties_length(num_properties, properties),
                         0, NULL);
  if (!wbuf)
    goto cleanup_properties;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE,
           OPCODE_DEVICE_FOUND_NTF);
  if (append_bt_property_t_array(&wbuf->buf.pdu,
                                 properties, num_properties) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  free(aligned_properties);

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
cleanup_properties:
  free(aligned_properties);
}

static void
discovery_state_changed_cb(bt_discovery_state_t state)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1, /* state */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE,
           OPCODE_DISCOVERY_STATE_CHANGED_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

#ifdef Q_BLUETOOTH
static void
pin_request_cb(bt_bdaddr_t* remote_bd_addr, bt_bdname_t* bd_name,
               uint32_t cod, uint8_t secure)
#else
static void
pin_request_cb(bt_bdaddr_t* remote_bd_addr, bt_bdname_t* bd_name,
               uint32_t cod)
#endif
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* remote address */
                         249 + /* remote name */
                         4, /* class of device */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE, OPCODE_PIN_REQUEST_NTF);
  if (append_bt_bdaddr_t(&wbuf->buf.pdu, remote_bd_addr) < 0)
    goto cleanup;
  if (append_bt_bdname_t(&wbuf->buf.pdu, bd_name) < 0)
    goto cleanup;
  if (append_to_pdu(&wbuf->buf.pdu, "I", cod) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
ssp_request_cb(bt_bdaddr_t* remote_bd_addr, bt_bdname_t* bd_name,
               uint32_t cod, bt_ssp_variant_t pairing_variant,
               uint32_t pass_key)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* remote address */
                         249 + /* remote name */
                         4 + /* class of device */
                         1 + /* paring variant */
                         4, /* passkey */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE, OPCODE_SSP_REQUEST_NTF);
  if (append_bt_bdaddr_t(&wbuf->buf.pdu, remote_bd_addr) < 0)
    goto cleanup;
  if (append_bt_bdname_t(&wbuf->buf.pdu, bd_name) < 0)
    goto cleanup;
  if (append_to_pdu(&wbuf->buf.pdu, "ICI", cod,
                    (uint8_t)pairing_variant, pass_key) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
bond_state_changed_cb(bt_status_t status, bt_bdaddr_t* remote_bd_addr,
                      bt_bond_state_t state)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* status */
                         6 + /* remote address */
                         1, /* bond state */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE, OPCODE_BOND_STATE_CHANGED_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)status) < 0)
    goto cleanup;
  if (append_bt_bdaddr_t(&wbuf->buf.pdu, remote_bd_addr) < 0)
    goto cleanup;
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
acl_state_changed_cb(bt_status_t status, bt_bdaddr_t* remote_bd_addr,
                     bt_acl_state_t state)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* status */
                         6 + /* remote address */
                         1, /* ACL state */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE, OPCODE_ACL_STATE_CHANGED_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)status) < 0)
    goto cleanup;
  if (append_bt_bdaddr_t(&wbuf->buf.pdu, remote_bd_addr) < 0)
    goto cleanup;
  if (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)state) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
thread_evt_cb(bt_cb_thread_evt evt ATTRIBS(UNUSED))
{
  /* nothing to do */
}

static void
dut_mode_recv_cb(uint16_t opcode, uint8_t* buf, uint8_t len)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(2 + /* opcode */
                         1 + /* buffer length */
                         len, /* buffer */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE, OPCODE_DUT_MODE_RECEIVE_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "SCm", opcode, len, buf, (size_t)len) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

#if ANDROID_VERSION >= 18
static void
le_test_mode_cb(bt_status_t status, uint16_t num_packets)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* status */
                         2, /* number of packets */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_CORE, OPCODE_LE_TEST_MODE_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "CS",
                    (uint8_t)status, (uint16_t)num_packets) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}
#endif

#if ANDROID_VERSION >= 21
static void
energy_info_cb(bt_activity_energy_info *energy_info ATTRIBS(UNUSED))
{
  /* nothing to do */
}

struct wake_alarm_param {
  struct fd_events evfuncs;
  int clockid;
  unsigned long long timeout_ms;
  unsigned long long interval_ms;
  alarm_cb cb;
  void* data;
};

static enum ioresult
alarm_event_in(int fd, void* data)
{
  struct wake_alarm_param* param = data;

  assert(param);

  if (param->cb)
    param->cb(param->data);

  remove_fd_from_epoll_loop(fd);
  if (TEMP_FAILURE_RETRY(close(fd)) < 0)
    ALOGW_ERRNO("close");
  free(param);

  return IO_POLL;
}

static enum ioresult
set_wake_alarm_task_cb(void* data)
{
  struct wake_alarm_param* param = data;

  assert(param);

  if (add_relative_timer_to_epoll_loop(param->clockid, param->timeout_ms,
                                       param->interval_ms, fd_events_handler,
                                       &param->evfuncs) < 0)
    goto err_add_relative_timer_to_epoll_loop;

  return IO_OK;
err_add_relative_timer_to_epoll_loop:
  free(param);
  return IO_OK;
}

static bool
set_wake_alarm_cb(uint64_t delay_millis, bool should_wake, alarm_cb cb,
                  void* data)
{
  struct wake_alarm_param* param;

  param = malloc(sizeof(*param));
  if (!param) {
    ALOGE_ERRNO("malloc");
    return false;
  }
  memset(&param->evfuncs, 0, sizeof(param->evfuncs));
  param->evfuncs.data = param;
  param->evfuncs.epollin = alarm_event_in;
  param->clockid = should_wake ? CLOCK_BOOTTIME_ALARM : CLOCK_BOOTTIME;
  param->timeout_ms = delay_millis;
  param->interval_ms = 0;
  param->cb = cb;
  param->data = data;

  if (run_task(set_wake_alarm_task_cb, param) < 0)
    goto err_run_task;

  return true;
err_run_task:
  free(param);
  return false;
}

static int
acquire_wake_lock_cb(const char* lock_name)
{
  acquire_wake_lock(PARTIAL_WAKE_LOCK, lock_name);
  return BT_STATUS_SUCCESS;
};

static int
release_wake_lock_cb(const char* lock_name)
{
  release_wake_lock(lock_name);
  return BT_STATUS_SUCCESS;
};
#endif

/*
 * Commands/Responses
 */

static bt_status_t
enable(const struct pdu* cmd)
{
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->enable);

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->enable();
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_enable;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_enable:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
disable(const struct pdu* cmd)
{
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->disable);

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->disable();
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_disable;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_disable:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
get_adapter_properties(const struct pdu* cmd)
{
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->get_adapter_properties);

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->get_adapter_properties();
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_get_adapter_properties;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_get_adapter_properties:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
get_adapter_property(const struct pdu* cmd)
{
  uint8_t type;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->get_adapter_property);

  if (read_pdu_at(cmd, 0, "C", &type) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->get_adapter_property(type);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_get_adapter_property;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_get_adapter_property:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
set_adapter_property(const struct pdu* cmd)
{
  bt_property_t property;
  int status;
  struct pdu_wbuf* wbuf;

  assert(bt_interface);
  assert(bt_interface->set_adapter_property);

  if (read_bt_property_t(cmd, 0, &property) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = bt_interface->set_adapter_property(&property);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_set_adapter_property;

  free(property.val);

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_set_adapter_property:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  free(property.val);
  return status;
}

static bt_status_t
get_remote_device_properties(const struct pdu* cmd)
{
  bt_bdaddr_t remote_addr;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->get_remote_device_properties);

  if (read_bt_bdaddr_t(cmd, 0, &remote_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->get_remote_device_properties(&remote_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_get_remote_device_properties;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_get_remote_device_properties:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
get_remote_device_property(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t remote_addr;
  uint8_t type;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->get_remote_device_property);

  off = read_bt_bdaddr_t(cmd, 0, &remote_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;
  if (read_pdu_at(cmd, off, "C", &type) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->get_remote_device_property(&remote_addr, type);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_get_remote_device_property;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_get_remote_device_property:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
set_remote_device_property(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t remote_addr;
  bt_property_t property;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->set_remote_device_property);

  off = read_bt_bdaddr_t(cmd, 0, &remote_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;
  if (read_bt_property_t(cmd, off, &property) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = bt_interface->set_remote_device_property(&remote_addr, &property);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_set_remote_device_property;

  free(property.val);

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_set_remote_device_property:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
  free(property.val);
  return status;
}

static bt_status_t
get_remote_service_record(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t remote_addr;
  bt_uuid_t uuid;
  struct pdu_wbuf* wbuf;
  struct get_remote_service_record_params* params;
  int status;

  assert(bt_interface);
  assert(bt_interface->get_remote_service_record);

  off = read_bt_bdaddr_t(cmd, 0, &remote_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;
  if (read_bt_uuid_t(cmd, off, &uuid) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  params = store_get_remote_service_record_params(&remote_addr, &uuid);
  if (!params) {
    status = BT_STATUS_NOMEM;
    goto err_store_get_remote_service_record_params;
  }

  status = bt_interface->get_remote_service_record(&remote_addr, &uuid);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_get_remote_service_record;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_get_remote_service_record:
  remove_get_remote_service_record_params(params);
err_store_get_remote_service_record_params:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
get_remote_services(const struct pdu* cmd)
{
  bt_bdaddr_t remote_addr;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->get_remote_services);

  if (read_bt_bdaddr_t(cmd, 0, &remote_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->get_remote_services(&remote_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_get_remote_services;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_get_remote_services:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
start_discovery(const struct pdu* cmd)
{
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->start_discovery);

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->start_discovery();
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_start_discovery;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_start_discovery:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
cancel_discovery(const struct pdu* cmd)
{
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->cancel_discovery);

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->cancel_discovery();
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_cancel_discovery;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_cancel_discovery:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
create_bond(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  int status;
#if ANDROID_VERSION >= 21
  uint8_t transport;
#endif

  assert(bt_interface);
  assert(bt_interface->create_bond);

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

#if ANDROID_VERSION >= 21
  if (read_pdu_at(cmd, off, "C", &transport) < 0)
    return BT_STATUS_PARM_INVALID;
#endif

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

#if ANDROID_VERSION >= 21
  status = bt_interface->create_bond(&bd_addr, transport);
#else
  status = bt_interface->create_bond(&bd_addr);
#endif
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_create_bond;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_create_bond:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
remove_bond(const struct pdu* cmd)
{
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->remove_bond);

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->remove_bond(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_remove_bond;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_remove_bond:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
cancel_bond(const struct pdu* cmd)
{
  bt_bdaddr_t bd_addr;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->cancel_bond);

  if (read_bt_bdaddr_t(cmd, 0, &bd_addr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->cancel_bond(&bd_addr);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_cancel_bond;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_cancel_bond:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
pin_reply(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  uint8_t accept;
  uint8_t pin_len;
  bt_pin_code_t pin_code;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->pin_reply);

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;
  off = read_pdu_at(cmd, off, "CC", &accept, &pin_len);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;
  if (read_bt_pin_code_t(cmd, off, &pin_code) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->pin_reply(&bd_addr, accept, pin_len, &pin_code);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_pin_reply;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_pin_reply:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
ssp_reply(const struct pdu* cmd)
{
  long off;
  bt_bdaddr_t bd_addr;
  uint8_t variant;
  uint8_t accept;
  uint32_t passkey;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->ssp_reply);

  off = read_bt_bdaddr_t(cmd, 0, &bd_addr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;
  if (read_pdu_at(cmd, off, "CCI", &variant, &accept, &passkey) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->ssp_reply(&bd_addr, variant, accept, passkey);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_ssp_reply;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_ssp_reply:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
dut_mode_configure(const struct pdu* cmd)
{
  uint8_t enable;
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->dut_mode_configure);

  if (read_pdu_at(cmd, 0, "C", &enable) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->dut_mode_configure(enable);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_dut_mode_configure;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_dut_mode_configure:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
dut_mode_send(const struct pdu* cmd)
{
  long off;
  uint16_t opcode;
  uint8_t len;
  uint8_t buf[256];
  struct pdu_wbuf* wbuf;
  int status;

  assert(bt_interface);
  assert(bt_interface->dut_mode_send);

  off = read_pdu_at(cmd, 0, "SC", &opcode, &len);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;
  if (read_pdu_at(cmd, off, "m", buf, len) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->dut_mode_send(opcode, buf, len);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_interface_dut_mode_send;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_interface_dut_mode_send:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

#if ANDROID_VERSION >= 18
static bt_status_t
le_test_mode(const struct pdu* cmd)
{
  long off;
  uint16_t opcode;
  uint8_t len;
  uint8_t buf[256];
  struct pdu_wbuf* wbuf;
  int status;

  off = read_pdu_at(cmd, 0, "SC", &opcode, &len);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;
  if (read_pdu_at(cmd, off, "m", buf, len) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = bt_interface->le_test_mode(opcode, buf, len);
  if (status != BT_STATUS_SUCCESS)
    goto err_bt_core_le_test_mode;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_bt_core_le_test_mode:
  cleanup_pdu_wbuf(wbuf);
  return status;
}
#endif

static bt_status_t
bt_core_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
    [OPCODE_ENABLE] = enable,
    [OPCODE_DISABLE] = disable,
    [OPCODE_GET_ADAPTER_PROPERTIES] = get_adapter_properties,
    [OPCODE_GET_ADAPTER_PROPERTY] = get_adapter_property,
    [OPCODE_SET_ADAPTER_PROPERTY] = set_adapter_property,
    [OPCODE_GET_REMOTE_DEVICE_PROPERTIES] = get_remote_device_properties,
    [OPCODE_GET_REMOTE_DEVICE_PROPERTY] = get_remote_device_property,
    [OPCODE_SET_REMOTE_DEVICE_PROPERTY] = set_remote_device_property,
    [OPCODE_GET_REMOTE_SERVICE_RECORD] = get_remote_service_record,
    [OPCODE_GET_REMOTE_SERVICES] = get_remote_services,
    [OPCODE_START_DISCOVERY] = start_discovery,
    [OPCODE_CANCEL_DISCOVERY] = cancel_discovery,
    [OPCODE_CREATE_BOND] = create_bond,
    [OPCODE_REMOVE_BOND] = remove_bond,
    [OPCODE_CANCEL_BOND] = cancel_bond,
    [OPCODE_PIN_REPLY] = pin_reply,
    [OPCODE_SSP_REPLY] = ssp_reply,
    [OPCODE_DUT_MODE_CONFIGURE] = dut_mode_configure,
    [OPCODE_DUT_MODE_SEND] = dut_mode_send
#if ANDROID_VERSION >= 18
    ,
    [OPCODE_LE_TEST_MODE] = le_test_mode
#endif
  };

  return handle_pdu_by_opcode(cmd, handler);
}

bt_status_t
(*register_bt_core(unsigned char mode ATTRIBS(UNUSED),
                   unsigned long max_num_clients ATTRIBS(UNUSED),
                   void (*send_pdu_cb)(struct pdu_wbuf*)))(const struct pdu*)
{
#define container(_t, _v, _m) \
  ( (_t*)( ((const unsigned char*)(_v)) - offsetof(_t, _m) ) )

  static bt_callbacks_t bt_callbacks = {
    .size = sizeof(bt_callbacks),
    .adapter_state_changed_cb = adapter_state_changed_cb,
    .adapter_properties_cb = adapter_properties_cb,
    .remote_device_properties_cb = remote_device_properties_cb,
    .device_found_cb = device_found_cb,
    .discovery_state_changed_cb = discovery_state_changed_cb,
    .pin_request_cb = pin_request_cb,
    .ssp_request_cb = ssp_request_cb,
    .bond_state_changed_cb = bond_state_changed_cb,
    .acl_state_changed_cb = acl_state_changed_cb,
    .thread_evt_cb = thread_evt_cb,
    .dut_mode_recv_cb = dut_mode_recv_cb,
#if ANDROID_VERSION >= 18
    .le_test_mode_cb = le_test_mode_cb,
#endif
#if ANDROID_VERSION >= 21
    .energy_info_cb = energy_info_cb
#endif
  };

#if ANDROID_VERSION >= 21
  static bt_os_callouts_t bt_os_callouts = {
    .size = sizeof(bt_os_callouts),
    .set_wake_alarm = set_wake_alarm_cb,
    .acquire_wake_lock = acquire_wake_lock_cb,
    .release_wake_lock = release_wake_lock_cb
  };
#endif

  int status;
  int err;
  hw_module_t* module;
  hw_device_t* device;

  assert(send_pdu_cb);

  if (bt_device) {
    ALOGE("Bluetooth device already open");
    return NULL;
  }

  if (bt_interface) {
    ALOGE("Bluetooth interface already set up");
    return NULL;
  }

  err = hw_get_module(BT_HARDWARE_MODULE_ID, (hw_module_t const**)&module);
  if (err) {
    ALOGE_ERRNO_NO("hw_get_module", err);
    return NULL;
  }

  err = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
  if (err) {
    ALOGE_ERRNO_NO("hw_module_t::methods::open", err);
    return NULL;
  }

  bt_device = container(bluetooth_device_t, device, common);

  bt_interface = bt_device->get_bluetooth_interface();
  if (!bt_interface) {
    ALOGE("bt_device_t::get_bluetooth_interface failed");
    goto err_bt_device_get_bluetooth_interface;
  }

  status = bt_interface->init(&bt_callbacks);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("bt_interface_t::init failed");
    goto err_bt_interface_init;
  }

#if ANDROID_VERSION >= 21
  status = bt_interface->set_os_callouts(&bt_os_callouts);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("bt_interface_t::set_os_callouts failed");
    goto err_bt_interface_set_os_callouts;
  }
#endif

  send_pdu = send_pdu_cb;

  return bt_core_handler;

#if ANDROID_VERSION >= 21
err_bt_interface_set_os_callouts:
  bt_interface->cleanup();
#endif
err_bt_interface_init:
  bt_interface = NULL;
err_bt_device_get_bluetooth_interface:
  bt_device = NULL;
  err = device->close(device);
  if (err)
    ALOGW_ERRNO_NO("hw_device_t::close", err);
  return NULL;

#undef container
}

int
unregister_bt_core()
{
  int err;

  assert(bt_interface);
  assert(bt_device);

  bt_interface->cleanup();
  bt_interface = NULL;

  err = bt_device->common.close(&bt_device->common);
  if (err)
    ALOGW_ERRNO_NO("bt_device_t::common::close", err);
  bt_device = NULL;

  return 0;
}

const void*
get_profile_interface(const char* profile_id)
{
  assert(bt_interface);
  assert(bt_interface->get_profile_interface);

  return bt_interface->get_profile_interface(profile_id);
}
