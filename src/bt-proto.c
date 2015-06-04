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
#include <stdarg.h>
#include "log.h"
#include "bt-proto.h"

void
init_pdu(struct pdu* pdu, uint8_t service, uint8_t opcode)
{
  assert(pdu);

  pdu->service = service;
  pdu->opcode = opcode;
  pdu->len = 0;
}

size_t
pdu_size(const struct pdu* pdu)
{
  return sizeof(*pdu) + pdu->len;
}

static bt_status_t
handle_pdu(const char* field, uint8_t value, const struct pdu* cmd,
           bt_status_t (* const handler[256])(const struct pdu*))
{
  assert(field);
  assert(cmd);
  assert(handler);

  if (!handler[value]) {
    ALOGE("unsupported %s 0x%x", field, value);
    return BT_STATUS_UNSUPPORTED;
  }
  return handler[value](cmd);
}

bt_status_t
handle_pdu_by_service(const struct pdu* cmd,
                      bt_status_t (* const handler[256])(const struct pdu*))
{
  return handle_pdu("service", cmd->service, cmd, handler);
}

bt_status_t
handle_pdu_by_opcode(const struct pdu* cmd,
                     bt_status_t (* const handler[256])(const struct pdu*))
{
  return handle_pdu("opcode", cmd->opcode, cmd, handler);
}

static ptrdiff_t
memdiff(const void* low, const void* high)
{
  return ((const char*)high) - ((const char*)low);
}

static long
read_pdu_at_va(const struct pdu* pdu, unsigned long offset,
               const char* fmt, va_list ap)
{
  void** mem;
  void* chr;
  void* dst;
  size_t len;

  for (; *fmt; ++fmt) {
    switch (*fmt) {
      case 'c': /* signed 8 bit */
        dst = va_arg(ap, int8_t*);
        len = sizeof(int8_t);
        break;
      case 'C': /* unsigned 8 bit*/
        dst = va_arg(ap, uint8_t*);
        len = sizeof(uint8_t);
        break;
      case 's': /* signed 16 bit */
        dst = va_arg(ap, int16_t*);
        len = sizeof(int16_t);
        break;
      case 'S': /* unsigned 16 bit */
        dst = va_arg(ap, uint16_t*);
        len = sizeof(uint16_t);
        break;
      case 'i': /* signed 32 bit */
        dst = va_arg(ap, int32_t*);
        len = sizeof(int32_t);
        break;
      case 'I': /* unsigned 32 bit */
        dst = va_arg(ap, uint32_t*);
        len = sizeof(uint32_t);
        break;
      case 'l': /* signed 64 bit */
        dst = va_arg(ap, int64_t*);
        len = sizeof(int64_t);
        break;
      case 'L': /* unsigned 64 bit */
        dst = va_arg(ap, uint64_t*);
        len = sizeof(uint64_t);
        break;
      case 'm': /* raw memory + length */
        dst = va_arg(ap, void*);
        len = va_arg(ap, size_t);
        break;
      case 'M': /* unallocated raw memory + length */
        mem = va_arg(ap, void**);
        len = va_arg(ap, size_t);
        dst = malloc(len);
        if (!dst) {
          ALOGE_ERRNO("malloc");
          return -1;
        }
        *mem = dst;
        break;
      case '0': /* raw 0-terminated memory */
        mem = va_arg(ap, void**);
        chr = memchr(pdu->data + offset, '\0', pdu->len - offset);
        if (!chr) {
          ALOGE("string not terminated");
          return -1;
        }
        len = memdiff(pdu->data + offset, chr) + 1; /* include \0 byte */
        dst = malloc(len);
        if (!dst) {
          ALOGE_ERRNO("malloc");
          return -1;
        }
        *mem = dst;
        break;
      default:
        ALOGE("invalid format character %c", *fmt);
        return -1;
    }
    if (offset+len > pdu->len) {
      ALOGE("PDU overflow");
      return -1;
    }
    memcpy(dst, pdu->data+offset, len);
    offset += len;
  }

  return offset;
}

long
read_pdu_at(const struct pdu* pdu, unsigned long offset, const char* fmt, ...)
{
  va_list ap;
  long res;

  va_start(ap, fmt);
  res = read_pdu_at_va(pdu, offset, fmt, ap);
  va_end(ap);

  return res;
}

long
read_bt_property_t(const struct pdu* pdu, unsigned long offset,
                   bt_property_t* property)
{
  uint8_t type;
  uint16_t len;
  long res;
  void* val;

  assert(property);

  res = read_pdu_at(pdu, offset, "CS", &type, &len);
  if (res < 0)
    return -1;
  offset = res;

  val = malloc(len);
  if (!val) {
    ALOGE_ERRNO("malloc");
    return -1;
  }

  res = read_pdu_at(pdu, offset, "m", val, (size_t)len);
  if (res < 0)
    goto err_read_pdu_at;
  offset = res;

  property->type = type;
  property->len = len;
  property->val = val;

  return offset;
err_read_pdu_at:
  free(val);
  return -1;
}

long
read_bt_bdaddr_t(const struct pdu* pdu, unsigned long offset,
                 bt_bdaddr_t* addr)
{
  assert(addr);

  return read_pdu_at(pdu, offset, "m", addr->address, (size_t)6);
}

long
read_bt_uuid_t(const struct pdu* pdu, unsigned long offset, bt_uuid_t* uuid)
{
  assert(uuid);

  return read_pdu_at(pdu, offset, "m", uuid->uu, (size_t)16);
}

long
read_bt_pin_code_t(const struct pdu* pdu, unsigned long offset,
                   bt_pin_code_t* pin_code)
{
  assert(pin_code);

  return read_pdu_at(pdu, offset, "m", pin_code->pin, (size_t)16);
}

static long
write_pdu_at_va(struct pdu* pdu, unsigned long offset, const char* fmt,
                va_list ap)
{
  int8_t c;
  uint8_t C;
  int16_t s;
  uint16_t S;
  int32_t i;
  uint32_t I;
  int64_t l;
  uint64_t L;
  const void* src;
  const void* chr;
  size_t len;

  for (; *fmt; ++fmt) {
    switch (*fmt) {
      case 'c': /* signed 8 bit */
        c = (int8_t)va_arg(ap, int);
        src = &c;
        len = sizeof(c);
        break;
      case 'C': /* unsigned 8 bit */
        C = (uint8_t)va_arg(ap, int);
        src = &C;
        len = sizeof(C);
        break;
      case 's': /* signed 16 bit */
        s = (int16_t)va_arg(ap, int);
        src = &s;
        len = sizeof(s);
        break;
      case 'S': /* unsigned 16 bit */
        S = (uint16_t)va_arg(ap, int);
        src = &S;
        len = sizeof(S);
        break;
      case 'i': /* signed 32 bit */
        i = va_arg(ap, int32_t);
        src = &i;
        len = sizeof(i);
        break;
      case 'I': /* unsigned 32 bit */
        I = va_arg(ap, uint32_t);
        src = &I;
        len = sizeof(I);
        break;
      case 'l': /* signed 64 bit */
        l = va_arg(ap, int64_t);
        src = &l;
        len = sizeof(l);
        break;
      case 'L': /* unsigned 64 bit */
        L = va_arg(ap, uint64_t);
        src = &L;
        len = sizeof(L);
        break;
      case 'm': /* raw memory + length */
      case 'M': /* raw memory + length */
        src = va_arg(ap, void*);
        len = va_arg(ap, size_t);
        break;
      case '0': /* raw 0-terminated memory */
        src = va_arg(ap, void*);
        chr = strchr(src, '\0');
        len = memdiff(src, chr) + 1; /* include \0 byte */
        break;
      default:
        ALOGE("invalid format character %c", *fmt);
        return -1;
    }
    memcpy(pdu->data+offset, src, len);
    offset += len;
  }

  return offset;
}

long
write_pdu_at(struct pdu* pdu, unsigned long offset, const char* fmt, ...)
{
  va_list ap;
  long res;

  va_start(ap, fmt);
  res = write_pdu_at_va(pdu, offset, fmt, ap);
  va_end(ap);

  return res;
}

long
append_to_pdu(struct pdu* pdu, const char* fmt, ...)
{
  va_list ap;
  long res;

  va_start(ap, fmt);
  res = write_pdu_at_va(pdu, pdu->len, fmt, ap);
  va_end(ap);

  if (res > 0)
    pdu->len = res;

  return res;
}

long
append_bt_property_t(struct pdu* pdu, const bt_property_t* property)
{
  uint8_t type = property->type;
  uint16_t len = property->len;
  const void* val = property->val;

  return append_to_pdu(pdu, "CSm", type, len, val, (size_t)len);
}

long
append_bt_property_t_array(struct pdu* pdu,
                           const bt_property_t* properties,
                           unsigned long num_properties)
{
  static const unsigned char property_type_is_valid[256] = {
    [BT_PROPERTY_BDNAME] = 1,
    [BT_PROPERTY_BDADDR] = 1,
    [BT_PROPERTY_UUIDS] = 1,
    [BT_PROPERTY_CLASS_OF_DEVICE] = 1,
    [BT_PROPERTY_TYPE_OF_DEVICE] = 1,
    [BT_PROPERTY_SERVICE_RECORD] = 1,
    [BT_PROPERTY_ADAPTER_SCAN_MODE] = 1,
    [BT_PROPERTY_ADAPTER_BONDED_DEVICES] = 1,
    [BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT] = 1,
    [BT_PROPERTY_REMOTE_FRIENDLY_NAME] = 1,
    [BT_PROPERTY_REMOTE_RSSI] = 1,
#if ANDROID_VERSION >= 18
    [BT_PROPERTY_REMOTE_VERSION_INFO] = 1,
#endif
    [BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP] = 1
  };

  long off, off1;
  unsigned long num_ignored, i;

  if (num_properties >= 256) {
    ALOGE("Too many properties in array");
    return -1;
  }

  /* 1) write number of properties */

  off = append_to_pdu(pdu, "C", (uint8_t)num_properties);
  if (off < 0)
    return -1;

  off1 = off - sizeof(uint8_t);

  /* 2) write properties */

  for (num_ignored = 0, i = 0; i < num_properties; ++i) {

    if (!property_type_is_valid[properties[i].type]) {
      ALOGD("Ignoring Bluetooth property of unknown type %d",
            (int)properties[i].type);
      ++num_ignored;
      continue;
    }

    off = append_bt_property_t(pdu, properties+i);
    if (off < 0)
      return -1;
  }

  /* 3) update number of properties if we ignored some */

  if (num_ignored) {
    if (write_pdu_at(pdu, off1, "C", (uint8_t)(num_properties-num_ignored)) < 0)
      return -1;
  }

  return off;
}

long
append_bt_bdaddr_t(struct pdu* pdu, const bt_bdaddr_t* addr)
{
  return append_to_pdu(pdu, "m", addr->address, (size_t)6);
}

long
append_bt_bdname_t(struct pdu* pdu, const bt_bdname_t* name)
{
  return append_to_pdu(pdu, "m", name->name, (size_t)249);
}

long
append_bt_uuid_t(struct pdu* pdu, const bt_uuid_t* uuid)
{
  assert(sizeof(uuid->uu) == 16);

  return append_to_pdu(pdu, "m", uuid->uu, sizeof(uuid->uu));
}
