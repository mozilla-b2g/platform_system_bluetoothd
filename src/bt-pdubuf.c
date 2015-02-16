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
#include <stdlib.h>
#include "log.h"
#include "bt-pdubuf.h"

struct pdu_rbuf*
create_pdu_rbuf(unsigned long maxdatalen)
{
  struct pdu_rbuf* rbuf;

  errno = 0;
  rbuf = malloc(sizeof(*rbuf) + maxdatalen);
  if (errno) {
    ALOGE_ERRNO("malloc");
    goto err_malloc;
  }

  rbuf->maxlen = sizeof(rbuf->buf) + maxdatalen;
  rbuf->len = 0;

  return rbuf;
err_malloc:
  return NULL;
}

void
cleanup_pdu_rbuf(struct pdu_rbuf* rbuf)
{
  /* |free| can deal with null pointers, but it's
   * certainly an error to pass one here.
   */
  assert(rbuf);

  free(rbuf);
}

int
pdu_rbuf_has_pdu_hdr(const struct pdu_rbuf* rbuf)
{
  assert(rbuf);
  return rbuf->len >= sizeof(rbuf->buf.pdu);
}

int
pdu_rbuf_has_pdu(const struct pdu_rbuf* rbuf)
{
  assert(rbuf);
  return pdu_rbuf_has_pdu_hdr(rbuf) && (rbuf->len == pdu_size(&rbuf->buf.pdu));
}

int
pdu_rbuf_is_full(const struct pdu_rbuf* rbuf)
{
  assert(rbuf);
  return rbuf->len == rbuf->maxlen;
}

struct pdu_wbuf*
create_pdu_wbuf(unsigned long maxdatalen, unsigned long taillen,
                int (*build_ancillary_data)(struct pdu_wbuf*, struct msghdr*))
{
  struct pdu_wbuf* wbuf;

  wbuf = malloc(sizeof(*wbuf) + maxdatalen + taillen);
  if (!wbuf) {
    ALOGE_ERRNO("malloc");
    goto err_malloc;
  }

  wbuf->stailq.stqe_next = NULL;
  wbuf->tailoff = maxdatalen;
  wbuf->maxlen = maxdatalen;
  wbuf->build_ancillary_data = build_ancillary_data;

  return wbuf;
err_malloc:
  return NULL;
}

void
cleanup_pdu_wbuf(struct pdu_wbuf* wbuf)
{
  assert(wbuf);
  free(wbuf);
}

#define CMSGHDR_CONTAINS_FD(_cmsghdr) \
  ( ((_cmsghdr)->cmsg_level == SOL_SOCKET) && \
    ((_cmsghdr)->cmsg_type == SCM_RIGHTS) )

#define CMSGHDR_FD(_cmsghdr) \
  (*((int*)CMSG_DATA(_cmsghdr)))

ssize_t
send_pdu_wbuf(struct pdu_wbuf* wbuf, int fd, int flags)
{
  struct iovec iov;
  struct msghdr msg;
  ssize_t res;
  struct cmsghdr* chdr;

  assert(wbuf);

  iov.iov_base = wbuf->buf.raw;
  iov.iov_len = pdu_size(&wbuf->buf.pdu);

  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;

  if (wbuf->build_ancillary_data) {
    if (wbuf->build_ancillary_data(wbuf, &msg) < 0)
      return -1;
  } else {
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
  }

  res = TEMP_FAILURE_RETRY(sendmsg(fd, &msg, flags));
  if (res < 0) {
    ALOGE_ERRNO("sendmsg");
    return -1;
  }

  /* File-descriptor transfers create a new reference to
   * the underlying open file description. We cleanup ours
   * here, so we won't leak resources.
   */

  chdr = CMSG_FIRSTHDR(&msg);

  for (; chdr; chdr = CMSG_NXTHDR(&msg, chdr)) {
    if (!CMSGHDR_CONTAINS_FD(chdr)) {
      continue;
    }
    if (TEMP_FAILURE_RETRY(close(CMSGHDR_FD(chdr))) < 0) {
      ALOGW_ERRNO("close");
    }
  }

  return res;
}

int
pdu_wbuf_consumed(const struct pdu_wbuf* wbuf)
{
  assert(wbuf);
  return wbuf->maxlen == pdu_size(&wbuf->buf.pdu);
}

void*
pdu_wbuf_tail(struct pdu_wbuf* wbuf)
{
  assert(wbuf);
  return wbuf->tail + wbuf->tailoff;
}
