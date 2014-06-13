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

#pragma once

#include <sys/queue.h>
#include <sys/socket.h>
#include "bt-proto.h"

struct pdu_rbuf {
  unsigned long maxlen;
  unsigned long len;
  union {
    struct pdu pdu;
    unsigned char raw[0];
  } buf;
};

struct pdu_rbuf*
create_pdu_rbuf(unsigned long maxdatalen);

void
cleanup_pdu_rbuf(struct pdu_rbuf* rbuf);

int
pdu_rbuf_has_pdu_hdr(const struct pdu_rbuf* rbuf);

int
pdu_rbuf_has_pdu(const struct pdu_rbuf* rbuf);

int
pdu_rbuf_is_full(const struct pdu_rbuf* rbuf);

struct pdu_wbuf {
  STAILQ_ENTRY(pdu_wbuf) stailq;
  unsigned long tailoff;
  unsigned long maxlen;
  int (*build_ancillary_data)(struct pdu_wbuf*, struct msghdr*);
  union {
    struct pdu pdu;
    unsigned char raw[0];
  } buf;
  unsigned char tail[0];
};

struct pdu_wbuf*
create_pdu_wbuf(unsigned long maxdatalen, unsigned long taillen,
                int (*build_ancillary_data)(struct pdu_wbuf*, struct msghdr*));

void
cleanup_pdu_wbuf(struct pdu_wbuf* wbuf);

ssize_t
send_pdu_wbuf(struct pdu_wbuf* wbuf, int fd, int flags);

int
pdu_wbuf_consumed(const struct pdu_wbuf* wbuf);

void*
pdu_wbuf_tail(struct pdu_wbuf* wbuf);
