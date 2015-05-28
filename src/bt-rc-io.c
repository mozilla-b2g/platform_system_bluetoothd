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

#if ANDROID_VERSION < 18
#error AVRCP support requires an Android SDK version of 18 or later
#endif

#include <assert.h>
#include <fdio/task.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_rc.h>
#include "compiler.h"
#include "log.h"
#include "bt-proto.h"
#include "bt-pdubuf.h"
#include "bt-core-io.h"
#include "bt-rc-io.h"

enum {
  /* commands/responses */
  OPCODE_GET_PLAY_STATUS_RSP = 0x01,
  OPCODE_LIST_PLAYER_APP_ATTR_RSP = 0x02,
  OPCODE_LIST_PLAYER_APP_VALUE_RSP = 0x03,
  OPCODE_GET_PLAYER_APP_VALUE_RSP = 0x04,
  OPCODE_GET_PLAYER_APP_ATTR_TEXT_RSP = 0x05,
  OPCODE_GET_PLAYER_APP_VALUE_TEXT_RSP = 0x06,
  OPCODE_GET_ELEMENT_ATTR_RSP = 0x07,
  OPCODE_SET_PLAYER_APP_VALUE_RSP = 0x08,
  OPCODE_REGISTER_NOTIFICATION_RSP = 0x09,
#if ANDROID_VERSION >= 19
  OPCODE_SET_VOLUME = 0x0a,
#endif
  /* notifications */
#if ANDROID_VERSION >= 19
  OPCODE_REMOTE_FEATURES_NTF = 0x81,
  OPCODE_GET_PLAY_STATUS_NTF = 0x82,
  OPCODE_LIST_PLAYER_APP_ATTR_NTF = 0x83,
  OPCODE_LIST_PLAYER_APP_VALUES_NTF = 0x84,
  OPCODE_GET_PLAYER_APP_VALUE_NTF = 0x85,
  OPCODE_GET_PLAYER_APP_ATTRS_TEXT_NTF = 0x86,
  OPCODE_GET_PLAYER_APP_VALUES_TEXT_NTF = 0x87,
  OPCODE_SET_PLAYER_APP_VALUE_NTF = 0x88,
  OPCODE_GET_ELEMENT_ATTR_NTF = 0x89,
  OPCODE_REGISTER_NOTIFICATION_NTF = 0x8a,
  OPCODE_VOLUME_CHANGE_NTF = 0x8b,
  OPCODE_PASSTHROUGH_CMD_NTF = 0x8c
#else /* defined by BlueZ 5.14 */
  OPCODE_GET_PLAY_STATUS_NTF = 0x81,
  OPCODE_LIST_PLAYER_APP_ATTR_NTF = 0x82,
  OPCODE_LIST_PLAYER_APP_VALUES_NTF = 0x83,
  OPCODE_GET_PLAYER_APP_VALUE_NTF = 0x84,
  OPCODE_GET_PLAYER_APP_ATTRS_TEXT_NTF = 0x85,
  OPCODE_GET_PLAYER_APP_VALUES_TEXT_NTF = 0x86,
  OPCODE_SET_PLAYER_APP_VALUE_NTF = 0x87,
  OPCODE_GET_ELEMENT_ATTR_NTF = 0x88,
  OPCODE_REGISTER_NOTIFICATION_NTF = 0x89
#endif
};

static void (*send_pdu)(struct pdu_wbuf* wbuf);
static const btrc_interface_t* btrc_interface;

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

long
read_btrc_player_attr_t(const struct pdu* pdu, unsigned long off,
                        btrc_player_attr_t* attr)
{
  long newoff;
  uint8_t value;

  newoff = read_pdu_at(pdu, off, "C", &value);
  if (newoff < 0)
    return -1;

  *attr = (btrc_player_attr_t)value;

  return newoff;
}

long
read_btrc_player_attr_t_array(const struct pdu* pdu, unsigned long off,
                              btrc_player_attr_t* attr,
                              unsigned long num_attrs)
{
  long newoff;
  unsigned long i;

  for (newoff = off, i = 0; (newoff >= 0) && (i < num_attrs); ++i) {
    newoff = read_btrc_player_attr_t(pdu, newoff, attr + i);
  }

  return newoff;
}

long
read_btrc_player_settings_t(const struct pdu* pdu, unsigned long off,
                            btrc_player_settings_t* settings)
{
  long newoff;
  uint8_t i;

  assert(settings);

  newoff = read_pdu_at(pdu, off, "C", &settings->num_attr);

  for (i = 0; (newoff >= 0) && (i < settings->num_attr); ++i) {
    newoff = read_pdu_at(pdu, newoff, "CC",
                         settings->attr_ids + i,
                         settings->attr_values + i);
  }

  return newoff;
}

long
read_btrc_player_setting_text_t(const struct pdu* pdu, unsigned long off,
                                btrc_player_setting_text_t* attr)
{
  long newoff;
  uint8_t len;

  assert(attr);

  newoff = read_pdu_at(pdu, off, "CC", &attr->id, &len);
  if (newoff < 0)
    return -1;
  newoff = read_pdu_at(pdu, newoff, "m", attr->text, len);

  return newoff;
}

long
read_btrc_player_setting_text_t_array(const struct pdu* pdu,
                                      unsigned long off,
                                      btrc_player_setting_text_t* attr,
                                      unsigned long num_attrs)
{
  long newoff;
  unsigned long i;

  assert(attr || !num_attrs);

  for (newoff = off, i = 0; (newoff >= 0) && (i < num_attrs); ++i) {
    newoff = read_btrc_player_setting_text_t(pdu, newoff, attr + i);
  }

  return newoff;
}

long
read_btrc_element_attr_val_t(const struct pdu* pdu, unsigned long off,
                             btrc_element_attr_val_t* attr)
{
  long newoff;
  uint8_t attr_id, len;

  assert(attr);

  newoff = read_pdu_at(pdu, off, "CC", &attr_id, &len);
  if (newoff < 0)
    return -1;

  attr->attr_id = attr_id;

  return read_pdu_at(pdu, newoff, "m", attr->text, len);
}

long
read_btrc_element_attr_val_t_array(const struct pdu* pdu, unsigned long off,
                                   btrc_element_attr_val_t* attr,
                                   unsigned long num_attrs)
{
  long newoff;
  unsigned long i;

  assert(attr || !num_attrs);

  for (newoff = off, i = 0; (newoff >= 0) && (i < num_attrs); ++i) {
    newoff = read_btrc_element_attr_val_t(pdu, newoff, attr + i);
  }

  return newoff;
}

long
read_btrc_play_status_t(const struct pdu* pdu, unsigned long off,
                        btrc_play_status_t* p_val)
{
  long newoff;
  uint8_t value;

  newoff = read_pdu_at(pdu, off, "C", &value);
  if (newoff < 0)
    return -1;

  *p_val = value;

  return newoff;
}

long
read_btrc_uid_t(const struct pdu* pdu, unsigned long off, btrc_uid_t p_val)
{
  return read_pdu_at(pdu, off, "m", p_val, BTRC_UID_SIZE);
}

long
read_btrc_register_notification_t(const struct pdu* pdu, unsigned long off,
                                  btrc_event_id_t event_id,
                                  btrc_register_notification_t *param)
{
  long newoff;
  uint8_t len;

  assert(param);

  newoff = read_pdu_at(pdu, off, "C", &len);

  switch (event_id) {
    case BTRC_EVT_PLAY_STATUS_CHANGED:
      newoff = read_btrc_play_status_t(pdu, newoff, &param->play_status);
      break;
    case BTRC_EVT_TRACK_CHANGE:
      newoff = read_btrc_uid_t(pdu, newoff, param->track);
      break;
    case BTRC_EVT_TRACK_REACHED_END:
    case BTRC_EVT_TRACK_REACHED_START:
      break;
    case BTRC_EVT_PLAY_POS_CHANGED:
      newoff = read_pdu_at(pdu, newoff, "I", &param->song_pos);
      break;
    case BTRC_EVT_APP_SETTINGS_CHANGED:
      newoff = read_btrc_player_settings_t(pdu, newoff, &param->player_setting);
      break;
    default:
      ALOGE("Unknown event id %d", (int)event_id);
      return -1;
  }

  return newoff;
}

long
append_btrc_player_attr_t_array(struct pdu* pdu,
                                const btrc_player_attr_t* attr,
                                unsigned long num_attrs)
{
  long off;
  unsigned long i;

  for (off = pdu->len, i = 0; (off >= 0) && (i < num_attrs); ++i) {
    off = append_to_pdu(pdu, "C", (uint8_t)attr[i]);
  }

  return off;
}

long
append_btrc_media_attr_t_array(struct pdu* pdu,
                               const btrc_media_attr_t* attr,
                               unsigned long num_attrs)
{
  long off;
  unsigned long i;

  for (off = pdu->len, i = 0; (off >= 0) && (i < num_attrs); ++i) {
    off = append_to_pdu(pdu, "C", (uint8_t)attr[i]);
  }

  return off;
}

long
append_btrc_player_settings_t(struct pdu* pdu,
                              const btrc_player_settings_t* settings)
{
  long off;
  unsigned long i;

  off = append_to_pdu(pdu, "C", settings->num_attr);

  for (i = 0; (off >= 0) && (i < settings->num_attr); ++i) {
    off = append_to_pdu(pdu, "CC", settings->attr_ids[i],
                                   settings->attr_values[i]);
  }

  return off;
}

/*
 * Notifications
 */

static void
get_play_status_cb(void)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_GET_PLAY_STATUS_NTF);

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
list_player_app_attr_cb(void)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_LIST_PLAYER_APP_ATTR_NTF);

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
list_player_app_values_cb(btrc_player_attr_t attr_id)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1, /* player attribute */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_LIST_PLAYER_APP_VALUES_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)attr_id) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
get_player_app_value_cb(uint8_t num_attr, btrc_player_attr_t* p_attrs)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* number of player attributes */
                         num_attr, /* one byte per attribute */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_GET_PLAYER_APP_VALUE_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "C", num_attr) < 0) ||
      (append_btrc_player_attr_t_array(&wbuf->buf.pdu, p_attrs, num_attr) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
get_player_app_attrs_text_cb(uint8_t num_attr, btrc_player_attr_t* p_attrs)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* number of attributes */
                         num_attr, /* one byte per attribute */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_GET_PLAYER_APP_ATTRS_TEXT_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "C", num_attr) < 0) ||
      (append_btrc_player_attr_t_array(&wbuf->buf.pdu, p_attrs, num_attr) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
get_player_app_values_text_cb(uint8_t attr_id, uint8_t num_val,
                              uint8_t* p_vals)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* attribute */
                         1 + /* number of values */
                         num_val, /* one byte per value */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_GET_PLAYER_APP_VALUES_TEXT_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "CCm", attr_id, num_val, p_vals, num_val) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
set_player_app_value_cb(btrc_player_settings_t* p_vals)
{
  struct pdu_wbuf* wbuf;

  assert(p_vals);

  wbuf = create_pdu_wbuf(1 + /* number of attribute-value pairs */
                         p_vals->num_attr + /* one byte per attribute */
                         p_vals->num_attr, /* one byte per value */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_SET_PLAYER_APP_VALUE_NTF);
  if (append_btrc_player_settings_t(&wbuf->buf.pdu, p_vals) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
get_element_attr_cb(uint8_t num_attr, btrc_media_attr_t* p_attrs)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* number of attributes */
                         num_attr, /* one byte per attribute */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_GET_ELEMENT_ATTR_NTF);
  if ((append_to_pdu(&wbuf->buf.pdu, "C", num_attr) < 0) ||
      (append_btrc_media_attr_t_array(&wbuf->buf.pdu, p_attrs, num_attr) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
register_notification_cb(btrc_event_id_t event_id, uint32_t param)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* event id */
                         4, /* parameter */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_REGISTER_NOTIFICATION_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "CI", (uint8_t)event_id, param) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

#if ANDROID_VERSION >= 19
static void
remote_features_cb(bt_bdaddr_t* bd_addr, btrc_remote_features_t features)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(6 + /* address */
                         1, /* feature bitmask */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_REMOTE_FEATURES_NTF);
  if ((append_bt_bdaddr_t(&wbuf->buf.pdu, bd_addr) < 0) ||
      (append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)features) < 0))
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
volume_change_cb(uint8_t volume, uint8_t ctype)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* volume */
                         1, /* type */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_VOLUME_CHANGE_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "CC", (uint8_t)volume, (uint8_t)ctype) < 0)
    goto cleanup;

  if (run_task(send_ntf_pdu, wbuf) < 0)
    goto cleanup;

  return;
cleanup:
  cleanup_pdu_wbuf(wbuf);
}

static void
passthrough_cmd_cb(int id, int key_state)
{
  struct pdu_wbuf* wbuf;

  wbuf = create_pdu_wbuf(1 + /* id */
                         1, /* state */
                         0, NULL);
  if (!wbuf)
    return;

  init_pdu(&wbuf->buf.pdu, SERVICE_BT_RC, OPCODE_PASSTHROUGH_CMD_NTF);
  if (append_to_pdu(&wbuf->buf.pdu, "CC", (uint8_t)id, (uint8_t)key_state) < 0)
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
opcode_get_play_status_rsp(const struct pdu* cmd)
{
  uint8_t play_status;
  uint32_t duration, position;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btrc_interface);
  assert(btrc_interface->get_play_status_rsp);

  if (read_pdu_at(cmd, 0, "CII", &play_status, &duration, &position) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = btrc_interface->get_play_status_rsp(play_status, duration, position);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_get_play_status_rsp;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btrc_interface_get_play_status_rsp:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_list_player_app_attr_rsp(const struct pdu* cmd)
{
  long off;
  uint8_t num_attr;
  btrc_player_attr_t p_attrs[256];
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btrc_interface);
  assert(btrc_interface->list_player_app_attr_rsp);

  off = read_pdu_at(cmd, 0, "C", &num_attr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  if (read_btrc_player_attr_t_array(cmd, off, p_attrs, num_attr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = btrc_interface->list_player_app_attr_rsp(num_attr, p_attrs);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_list_player_app_attr_rsp;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btrc_interface_list_player_app_attr_rsp:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_list_player_app_value_rsp(const struct pdu* cmd)
{
  long off;
  uint8_t num_attr;
  uint8_t p_vals[256];
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btrc_interface);
  assert(btrc_interface->list_player_app_value_rsp);

  off = read_pdu_at(cmd, 0, "C", &num_attr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  if (read_pdu_at(cmd, off, "m", p_vals, num_attr) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = btrc_interface->list_player_app_value_rsp(num_attr, p_vals);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_list_player_app_value_rsp;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btrc_interface_list_player_app_value_rsp:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_get_player_app_value_rsp(const struct pdu* cmd)
{
  btrc_player_settings_t p_vals;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btrc_interface);
  assert(btrc_interface->get_player_app_value_rsp);

  if (read_btrc_player_settings_t(cmd, 0, &p_vals) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = btrc_interface->get_player_app_value_rsp(&p_vals);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_get_player_app_value_rsp;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btrc_interface_get_player_app_value_rsp:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_get_player_app_attr_text_rsp(const struct pdu* cmd)
{
  long off;
  uint8_t num_attr;
  btrc_player_setting_text_t* p_attrs;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btrc_interface);
  assert(btrc_interface->get_player_app_attr_text_rsp);

  off = read_pdu_at(cmd, 0, "C", &num_attr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  p_attrs = malloc(num_attr * sizeof(*p_attrs));
  if (!p_attrs) {
    ALOGE_ERRNO("malloc");
    return BT_STATUS_NOMEM;
  }

  off = read_btrc_player_setting_text_t_array(cmd, off, p_attrs, num_attr);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_btrc_player_setting_text_t_array;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = btrc_interface->get_player_app_attr_text_rsp(num_attr, p_attrs);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_get_player_app_attr_text_rsp;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(p_attrs);

  return BT_STATUS_SUCCESS;
err_btrc_interface_get_player_app_attr_text_rsp:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
err_read_btrc_player_setting_text_t_array:
  free(p_attrs);
  return status;
}

static bt_status_t
opcode_get_player_app_value_text_rsp(const struct pdu* cmd)
{
  long off;
  uint8_t num_attr;
  btrc_player_setting_text_t* p_attrs;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btrc_interface);
  assert(btrc_interface->get_player_app_value_text_rsp);

  off = read_pdu_at(cmd, 0, "C", &num_attr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  p_attrs = malloc(num_attr * sizeof(*p_attrs));
  if (!p_attrs) {
    ALOGE_ERRNO("malloc");
    return BT_STATUS_NOMEM;
  }

  off = read_btrc_player_setting_text_t_array(cmd, off, p_attrs, num_attr);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_btrc_player_setting_text_t_array;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = btrc_interface->get_player_app_value_text_rsp(num_attr, p_attrs);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_get_player_app_value_text_rsp;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(p_attrs);

  return BT_STATUS_SUCCESS;
err_btrc_interface_get_player_app_value_text_rsp:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
err_read_btrc_player_setting_text_t_array:
  free(p_attrs);
  return status;
}

static bt_status_t
opcode_get_element_attr_rsp(const struct pdu* cmd)
{
  long off;
  uint8_t num_attr;
  btrc_element_attr_val_t* p_attrs;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btrc_interface);
  assert(btrc_interface->get_element_attr_rsp);

  off = read_pdu_at(cmd, 0, "C", &num_attr);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  p_attrs = malloc(num_attr * sizeof(*p_attrs));
  if (!p_attrs) {
    ALOGE_ERRNO("malloc");
    return BT_STATUS_NOMEM;
  }

  off = read_btrc_element_attr_val_t_array(cmd, off, p_attrs, num_attr);
  if (off < 0) {
    status = BT_STATUS_PARM_INVALID;
    goto err_read_btrc_element_attr_val_t_array;
  }

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf) {
    status = BT_STATUS_NOMEM;
    goto err_create_pdu_wbuf;
  }

  status = btrc_interface->get_element_attr_rsp(num_attr, p_attrs);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_get_element_attr_rsp;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  free(p_attrs);

  return BT_STATUS_SUCCESS;
err_btrc_interface_get_element_attr_rsp:
  cleanup_pdu_wbuf(wbuf);
err_create_pdu_wbuf:
err_read_btrc_element_attr_val_t_array:
  free(p_attrs);
  return status;
}

static bt_status_t
opcode_set_player_app_value_rsp(const struct pdu* cmd)
{
  uint8_t rsp_status;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btrc_interface);
  assert(btrc_interface->set_player_app_value_rsp);

  if (read_pdu_at(cmd, 0, "C", &rsp_status) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = btrc_interface->set_player_app_value_rsp(rsp_status);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_set_player_app_value_rsp;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btrc_interface_set_player_app_value_rsp:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

static bt_status_t
opcode_register_notification_rsp(const struct pdu* cmd)
{
  long off;
  uint8_t event_id, type;
  btrc_register_notification_t param;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  assert(btrc_interface);
  assert(btrc_interface->register_notification_rsp);

  off = read_pdu_at(cmd, 0, "CC", &event_id, &type);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  off = read_btrc_register_notification_t(cmd, off, event_id, &param);
  if (off < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  status = btrc_interface->register_notification_rsp(event_id, type, &param);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_register_notification_rsp;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btrc_interface_register_notification_rsp:
  cleanup_pdu_wbuf(wbuf);
  return status;
}

#if ANDROID_VERSION >= 19
static bt_status_t
opcode_set_volume(const struct pdu* cmd)
{
  uint8_t volume;
  struct pdu_wbuf* wbuf;
  bt_status_t status;

  if (read_pdu_at(cmd, 0, "C", &volume) < 0)
    return BT_STATUS_PARM_INVALID;

  wbuf = create_pdu_wbuf(0, 0, NULL);
  if (!wbuf)
    return BT_STATUS_NOMEM;

  assert(btrc_interface);
  assert(btrc_interface->set_volume);

  status = btrc_interface->set_volume(volume);
  if (status != BT_STATUS_SUCCESS)
    goto err_btrc_interface_set_volume;

  init_pdu(&wbuf->buf.pdu, cmd->service, cmd->opcode);
  send_pdu(wbuf);

  return BT_STATUS_SUCCESS;
err_btrc_interface_set_volume:
  cleanup_pdu_wbuf(wbuf);
  return status;
}
#endif

static bt_status_t
bt_rc_handler(const struct pdu* cmd)
{
  static bt_status_t (* const handler[256])(const struct pdu*) = {
    [OPCODE_GET_PLAY_STATUS_RSP] = opcode_get_play_status_rsp,
    [OPCODE_LIST_PLAYER_APP_ATTR_RSP] = opcode_list_player_app_attr_rsp,
    [OPCODE_LIST_PLAYER_APP_VALUE_RSP] = opcode_list_player_app_value_rsp,
    [OPCODE_GET_PLAYER_APP_VALUE_RSP] = opcode_get_player_app_value_rsp,
    [OPCODE_GET_PLAYER_APP_ATTR_TEXT_RSP] = opcode_get_player_app_attr_text_rsp,
    [OPCODE_GET_PLAYER_APP_VALUE_TEXT_RSP] = opcode_get_player_app_value_text_rsp,
    [OPCODE_GET_ELEMENT_ATTR_RSP] = opcode_get_element_attr_rsp,
    [OPCODE_SET_PLAYER_APP_VALUE_RSP] = opcode_set_player_app_value_rsp,
    [OPCODE_REGISTER_NOTIFICATION_RSP] = opcode_register_notification_rsp
#if ANDROID_VERSION >= 19
    ,
    [OPCODE_SET_VOLUME] = opcode_set_volume
#endif
  };

  return handle_pdu_by_opcode(cmd, handler);
}

bt_status_t
(*register_bt_rc(
  unsigned char mode ATTRIBS(UNUSED),
  unsigned long max_num_clients ATTRIBS(UNUSED),
  void (*send_pdu_cb)(struct pdu_wbuf*) ATTRIBS(UNUSED)))(const struct pdu*)
{
  static btrc_callbacks_t btrc_callbacks = {
    .size = sizeof(btrc_callbacks),
#if ANDROID_VERSION >= 19
    .remote_features_cb = remote_features_cb,
#endif
    .get_play_status_cb = get_play_status_cb,
    .list_player_app_attr_cb = list_player_app_attr_cb,
    .list_player_app_values_cb = list_player_app_values_cb,
    .get_player_app_value_cb = get_player_app_value_cb,
    .get_player_app_attrs_text_cb = get_player_app_attrs_text_cb,
    .get_player_app_values_text_cb = get_player_app_values_text_cb,
    .set_player_app_value_cb = set_player_app_value_cb,
    .get_element_attr_cb = get_element_attr_cb,
    .register_notification_cb = register_notification_cb
#if ANDROID_VERSION >= 19
    ,
    .volume_change_cb = volume_change_cb,
    .passthrough_cmd_cb = passthrough_cmd_cb
#endif
  };

  bt_status_t status;

  if (btrc_interface) {
    ALOGE("AVRCP interface already set up");
    return NULL;
  }

  btrc_interface = get_profile_interface(BT_PROFILE_AV_RC_ID);
  if (!btrc_interface) {
    ALOGE("get_profile_interface(BT_PROFILE_AV_RC_ID) failed");
    return NULL;
  }

  assert(btrc_interface->init);
  status = btrc_interface->init(&btrc_callbacks);
  if (status != BT_STATUS_SUCCESS) {
    ALOGE("btrc_interface_t::init failed");
    return NULL;
  }

  send_pdu = send_pdu_cb;

  return bt_rc_handler;
}

int
unregister_bt_rc()
{
  assert(btrc_interface);
  assert(btrc_interface->cleanup);

  btrc_interface->cleanup();
  btrc_interface = NULL;

  return 0;
}
