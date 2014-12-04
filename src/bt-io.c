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
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cutils/sockets.h>
#include <fdio/loop.h>
#include "compiler.h"
#include "log.h"
#include "bt-proto.h"
#include "bt-pdubuf.h"
#include "service.h"
#include "core.h"
#include "core-io.h"
#include "bt-io.h"

#define ARRAY_LENGTH(_array) \
  ( sizeof(_array) / sizeof((_array)[0]) )

static const char BLUETOOTHD_SOCKET[] = "bluez_hal_socket";

/*
 * Socket I/O
 */

static enum ioresult
io_fd0_event(int fd, uint32_t events, void* data);

static enum ioresult
io_fd1_event(int fd, uint32_t events, void* data);

STAILQ_HEAD(pdu_wbuf_stailq, pdu_wbuf);

struct io_state {
  int fd;
  uint32_t epoll_events;
  enum ioresult (*epoll_func)(int, uint32_t, void*);
  struct pdu_rbuf* rbuf;
  struct pdu_wbuf_stailq sendq;
};

static void
io_state_err(struct io_state* io_state)
{
  assert(io_state);

  if (io_state->rbuf) {
    cleanup_pdu_rbuf(io_state->rbuf);
    io_state->rbuf = NULL;
  }
  remove_fd_from_epoll_loop(io_state->fd);
  TEMP_FAILURE_RETRY(close(io_state->fd)); /* no error checks here */
  io_state->epoll_events = 0;
  io_state->fd = -1;
}

static void
io_state_hup(struct io_state* io_state)
{
  assert(io_state);

  if (io_state->rbuf) {
    cleanup_pdu_rbuf(io_state->rbuf);
    io_state->rbuf = NULL;
  }
  remove_fd_from_epoll_loop(io_state->fd);
  if (TEMP_FAILURE_RETRY(close(io_state->fd)) < 0)
    ALOGW_ERRNO("close");
  io_state->epoll_events = 0;
  io_state->fd = -1;
}

static int
io_state_in(struct io_state* io_state, int (*handle_pdu)(const struct pdu*))
{
  struct iovec iv;
  struct msghdr msg;
  ssize_t res;

  assert(io_state);
  assert(handle_pdu);

  memset(&iv, 0, sizeof(iv));
  iv.iov_base = io_state->rbuf->buf.raw;
  iv.iov_len = io_state->rbuf->maxlen;

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iv;
  msg.msg_iovlen = 1;

  res = TEMP_FAILURE_RETRY(recvmsg(io_state->fd, &msg, 0));
  if (res < 0) {
    ALOGE_ERRNO("recvmsg");
    return -1;
  } else if (!res) {
    /* stop watching if peer hung up */

    io_state->epoll_events &= ~EPOLLIN;

    if (io_state->epoll_events) {
      res = add_fd_to_epoll_loop(io_state->fd,
                                 io_state->epoll_events,
                                 io_state->epoll_func, io_state);
      if (res < 0)
        goto err_add_fd_to_epoll_loop;
    } else {
      remove_fd_from_epoll_loop(io_state->fd);
    }
  }

  io_state->rbuf->len = res;

  if (pdu_rbuf_has_pdu(io_state->rbuf)) {
    if (handle_pdu(&io_state->rbuf->buf.pdu) < 0)
      goto err_pdu;
    io_state->rbuf->len = 0;
  } else if (pdu_rbuf_is_full(io_state->rbuf)) {
    ALOGE("buffer too small for PDU(0x%x:0x%x)",
          io_state->rbuf->buf.pdu.service, io_state->rbuf->buf.pdu.opcode);
    goto err_pdu;
  }

  return 0;
err_pdu:
err_add_fd_to_epoll_loop:
  return -1;
}

static int
io_state_out(struct io_state* io_state)
{
  struct pdu_wbuf* wbuf;
  int res;

  assert(io_state);

  if (!STAILQ_EMPTY(&io_state->sendq)) {
    /* send next pending PDU */

    wbuf = STAILQ_FIRST(&io_state->sendq);
    STAILQ_REMOVE_HEAD(&io_state->sendq, stailq);

    send_pdu_wbuf(wbuf, io_state->fd, 0);
    cleanup_pdu_wbuf(wbuf);
  }

  if (STAILQ_EMPTY(&io_state->sendq)) {
    /* stop watching */

    io_state->epoll_events &= ~EPOLLOUT;

    if (io_state->epoll_events) {
      res = add_fd_to_epoll_loop(io_state->fd,
                                 io_state->epoll_events,
                                 io_state->epoll_func, io_state);
      if (res < 0)
        goto err_add_fd_to_epoll_loop;
    } else {
      remove_fd_from_epoll_loop(io_state->fd);
    }
  }

  return 0;
err_add_fd_to_epoll_loop:
  return -1;
}

static int
io_state_send(struct io_state* io_state, struct pdu_wbuf* wbuf)
{
  uint32_t epoll_events;
  int res;

  STAILQ_INSERT_TAIL(&io_state->sendq, wbuf, stailq);

  if (io_state->epoll_events & EPOLLOUT)
    return 0;

  /* poll file descriptor for writeability */

  epoll_events = io_state->epoll_events | EPOLLOUT;

  res = add_fd_to_epoll_loop(io_state->fd, epoll_events,
                             io_state->epoll_func, io_state);
  if (res < 0)
    goto err_add_fd_to_epoll_loop;

  io_state->epoll_events = epoll_events;

  return 0;
err_add_fd_to_epoll_loop:
  STAILQ_REMOVE(&io_state->sendq, wbuf, pdu_wbuf, stailq);
  cleanup_pdu_wbuf(wbuf);
  return -1;
}

#define IO_STATE_INITIALIZER(_io_state, _epoll_func) \
  { \
    .fd = -1, \
    .epoll_events = 0, \
    .epoll_func = (_epoll_func), \
    .rbuf = NULL, \
    STAILQ_HEAD_INITIALIZER((_io_state).sendq) \
  }

static struct io_state io_state[2] = {
  IO_STATE_INITIALIZER(io_state[0], io_fd0_event),
  IO_STATE_INITIALIZER(io_state[1], io_fd1_event)
};

static void
send_pdu(struct pdu_wbuf* wbuf)
{
  unsigned int i;

  i = !!(wbuf->buf.pdu.opcode & 0x80); /* 1 for notifications, 0 otherwise */

  io_state_send(io_state + i, wbuf);
}

static int
handle_pdu(const struct pdu* cmd)
{
  bt_status_t status;
  struct pdu_wbuf* wbuf;

  status = handle_pdu_by_service(cmd, service_handler);
  if (status != BT_STATUS_SUCCESS)
    goto err_handle_pdu_by_service;

  return 0;
err_handle_pdu_by_service:
  /* reply with an error */
  wbuf = create_pdu_wbuf(1, 0, NULL);
  if (!wbuf)
    return -1;
  init_pdu(&wbuf->buf.pdu, cmd->service, 0);
  append_to_pdu(&wbuf->buf.pdu, "C", (uint8_t)status);
  send_pdu(wbuf);
  return 0; /* signal success because we replied with an error */
}

static enum ioresult
io_fd_event_err(int fd ATTRIBS(UNUSED), void* data)
{
  struct io_state* io_state;

  assert(data);

  io_state = data;
  assert(io_state->fd == fd);

  io_state_err(io_state);

  return IO_POLL;
}

static enum ioresult
io_fd_event_hup(int fd ATTRIBS(UNUSED), void* data)
{
  struct io_state* io_state;

  assert(data);

  io_state = data;
  assert(io_state->fd == fd);

  io_state_hup(io_state);

  return IO_POLL;
}

static enum ioresult
io_fd_event_in(int fd ATTRIBS(UNUSED), void* data)
{
  struct io_state* io_state;

  assert(data);

  io_state = data;
  assert(io_state->fd == fd);

  if (io_state_in(io_state, handle_pdu) < 0)
    return IO_ABORT;

  return IO_OK;
}

static enum ioresult
io_fd_event_out(int fd ATTRIBS(UNUSED), void* data)
{
  struct io_state* io_state;

  assert(data);

  io_state = data;
  assert(io_state->fd == fd);

  if (io_state_out(io_state) < 0)
    return IO_ABORT;

  return IO_OK;
}

/* Command socket
 */

/* The function |io_fd0_event| handles the command/response file
 * descriptor. It supports IN and OUT events for receiving and
 * sending PDUs. HUP and ERROR are always handled.
 */
static enum ioresult
io_fd0_event(int fd, uint32_t events, void* data)
{
  enum ioresult res;

  if (events & EPOLLERR) {
    res = io_fd_event_err(fd, data);
  } else if (events & EPOLLHUP) {
    res = io_fd_event_hup(fd, data);
  } else if (events & EPOLLIN) {
    res = io_fd_event_in(fd, data);
  } else if (events & EPOLLOUT) {
    res = io_fd_event_out(fd, data);
  } else {
    ALOGW("unsupported event mask: %u", events);
    res = IO_OK;
  }
  return res;
}

/* Notification socket
 */

/* The function |io_fd1_event| handles the notification file
 * descriptor. We only send on this file descriptor, so the
 * function only supports OUT events for sending PDUs. HUP
 * and ERROR are always handled.
 */
static enum ioresult
io_fd1_event(int fd, uint32_t events, void* data)
{
  enum ioresult res;

  if (events & EPOLLERR) {
    res = io_fd_event_err(fd, data);
  } else if (events & EPOLLHUP) {
    res = io_fd_event_hup(fd, data);
  } else if (events & EPOLLOUT) {
    res = io_fd_event_out(fd, data);
  } else {
    ALOGW("unsupported event mask: %u", events);
    res = IO_OK;
  }
  return res;
}

/*
 * Listening socket I/O
 */

static enum ioresult
fd_event_err(int fd, void* data ATTRIBS(UNUSED))
{
  remove_fd_from_epoll_loop(fd);
  return IO_OK;
}

/* The first connected socket is for pairs of command/respond PDUs.
 */
static enum ioresult
accept_cmd_socket(int fd ATTRIBS(UNUSED), int socket_fd,
                  void* data ATTRIBS(UNUSED))
{
  struct pdu_rbuf* rbuf;

  rbuf = create_pdu_rbuf(1ul<<16);
  if (!rbuf)
    goto err_create_pdu_rbuf;

  io_state[0].fd = socket_fd;
  io_state[0].epoll_events = 0;
  io_state[0].rbuf = rbuf;

  return IO_OK;
err_create_pdu_rbuf:
  if (TEMP_FAILURE_RETRY(close(socket_fd)) < 0)
    ALOGW_ERRNO("close");
  return IO_ABORT;

}

/* The second connected socket is for notifications.
 */
static enum ioresult
accept_ntf_socket(int fd ATTRIBS(UNUSED), int socket_fd,
                  void* data ATTRIBS(UNUSED))
{
  uint32_t epoll_events;
  int res;

  io_state[1].fd = socket_fd;
  io_state[1].epoll_events = 0;
  io_state[1].rbuf = NULL;

  /* Init Bluedroid core module and I/O */

  if (init_core_io(send_pdu) < 0)
    goto err_init_core_io;

  /* Start listening on command socket */

  epoll_events = io_state[0].epoll_events | EPOLLERR|EPOLLIN;

  res = add_fd_to_epoll_loop(io_state[0].fd, epoll_events,
                             io_fd0_event, io_state + 0);
  if (res < 0) {
    goto err_add_fd_to_epoll_loop_0;
  }

  io_state[0].epoll_events = epoll_events;

  /* Start listening on notification socket; no EPOLLIN here */

  epoll_events = io_state[1].epoll_events | EPOLLERR;

  res = add_fd_to_epoll_loop(io_state[1].fd, epoll_events,
                             io_fd1_event, io_state + 1);
  if (res < 0) {
    goto err_add_fd_to_epoll_loop_1;
  }

  io_state[1].epoll_events = epoll_events;

  return IO_OK;
err_add_fd_to_epoll_loop_1:
  io_state[0].epoll_events &= ~(EPOLLERR|EPOLLIN);
  remove_fd_from_epoll_loop(io_state[0].fd);
err_add_fd_to_epoll_loop_0:
  uninit_core_io();
err_init_core_io:
  if (TEMP_FAILURE_RETRY(close(socket_fd)) < 0)
    ALOGW_ERRNO("close");
  return IO_ABORT;

}

static enum ioresult
fd_event_in(int fd, void* data)
{
  static enum ioresult (* const accept_next_socket[])(int, int, void*) = {
    [0] = accept_cmd_socket,
    [1] = accept_ntf_socket
  };

  int socket_fd;
  size_t i;

  socket_fd = TEMP_FAILURE_RETRY(accept(fd, NULL, 0));
  if (socket_fd < 0) {
    ALOGE_ERRNO("accept");
    goto err_accept;
  }

  for (i = 0; i < ARRAY_LENGTH(accept_next_socket); ++i) {
    if (io_state[i].fd == -1) {
      break;
    }
  }

  if (i == ARRAY_LENGTH(accept_next_socket)) {
    ALOGW("Too many connected sockets");
    if (TEMP_FAILURE_RETRY(close(socket_fd)) < 0)
      ALOGW_ERRNO("close");
    return IO_OK; /* no error, simply ignore connect request */
  }

  assert(accept_next_socket[i]);
  return accept_next_socket[i](fd, socket_fd, data);

err_accept:
  return IO_ABORT;
}

/* |fd_event| handles the listen file descriptor for incoming
 * connection requests. ERR is always handled.
 */
static enum ioresult
fd_event(int fd, uint32_t events, void* data)
{
  enum ioresult res;

  if (events & EPOLLERR) {
    res = fd_event_err(fd, data);
  } else if (events & EPOLLIN) {
    res = fd_event_in(fd, data);
  } else {
    ALOGW("unsupported event mask: %u", events);
    res = IO_OK;
  }

  return res;
}

int
init_bt_io()
{
  static const size_t NAME_OFFSET = 1;
  static const int LISTEN_BACKLOG = 2; /* enough for cmd and ntf connects */

  int fd;
  struct sockaddr_un addr;
  socklen_t socklen;

  fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd < 0) {
    ALOGE_ERRNO("socket");
    goto err_android_get_control_socket;
  }
  if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFL, O_NONBLOCK)) < 0) {
    ALOGE_ERRNO("fcntl");
    goto err_fcntl;
  }

  addr.sun_family = AF_UNIX;
  assert(NAME_OFFSET + sizeof(BLUETOOTHD_SOCKET) <= sizeof(addr.sun_path));
  memset(addr.sun_path, '\0', NAME_OFFSET); /* abstract socket */
  memcpy(addr.sun_path + NAME_OFFSET, BLUETOOTHD_SOCKET,
         sizeof(BLUETOOTHD_SOCKET));

  socklen = offsetof(struct sockaddr_un, sun_path) +
                     NAME_OFFSET + sizeof(BLUETOOTHD_SOCKET);

  if (bind(fd, (const struct sockaddr*)&addr, socklen) < 0) {
    ALOGE_ERRNO("bind");
    goto err_bind;
  }

  if (listen(fd, LISTEN_BACKLOG) < 0) {
    ALOGE_ERRNO("listen");
    goto err_listen;
  }

  if (add_fd_to_epoll_loop(fd, EPOLLIN|EPOLLERR, fd_event, NULL) < 0)
    goto err_add_fd_to_epoll_loop;

  return 0;
err_add_fd_to_epoll_loop:
err_listen:
err_bind:
err_fcntl:
  if (TEMP_FAILURE_RETRY(close(fd)) < 0)
    ALOGW_ERRNO("close");
err_android_get_control_socket:
  return -1;
}
