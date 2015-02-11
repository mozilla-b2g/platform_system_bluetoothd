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

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <hardware_legacy/power.h>
#include <fdio/loop.h>
#include "compiler.h"
#include "log.h"

#undef LOG_TAG
#define LOG_TAG  "bluetoothd-snoop"

#define ARRAY_LENGTH(_array) \
  ( sizeof(_array) / sizeof((_array)[0]) )

struct options {
  const char* socket_name;
};

static const char WAKE_LOCK_NAME[] = "bluetoothd-snoop";

static int
parse_opt_a(int c ATTRIBS(unused), char* arg, struct options* opt)
{
  if (!arg) {
    fprintf(stderr, "Error: No network address specified.");
    return -1;
  }
  if (!strlen(arg)) {
    fprintf(stderr, "Error: The specified network address is empty.");
    return -1;
  }
  opt->socket_name = arg;

  return 0;
}

static int
parse_opt_h(int c ATTRIBS(unused), char* arg ATTRIBS(UNUSED),
            struct options* opt ATTRIBS(UNUSED))
{
  printf("Usage: bluetoothd-snoop [OPTION]\n"
         "Enables HCI snooping for bluetoothd\n"
         "\n"
         "General options:\n"
         "  -h    displays this help\n"
         "\n"
         "Networking:\n"
         "  -a    the network address\n"
         "\n"
         "The only supported address family is AF_UNIX with abstract "
         "names.\n");

  return 1;
}

static int
parse_opt_question_mark(int c,
                        char* arg ATTRIBS(UNUSED),
                        struct options* opt ATTRIBS(UNUSED))
{
  fprintf(stderr, "Unknown option %c\n", c);

  return -1;
}

static void
make_daemon(void)
{
  /* Create new session; disconnect from controlling terminal */
  if ((setsid() < 0 && errno != EPERM))
    ALOGW_ERRNO("setsid");

  /* Clear file creation mask */
  umask(0);

  /* Change to root dir; allow unmounting previous working directory */
  if (chdir("/") < 0)
    ALOGW_ERRNO("chdir");

  /* Normally we would now close all open file descriptors and re-
   * open the standard file descriptors to 'dev/null'. On Android,
   * this breaks the logging system, so we leave the file descriptors
   * open.
   */
}

static int
connect_socket(const char* socket_name,
               enum ioresult (*func)(int, uint32_t, void*),
               void* data)
{
  static const size_t NAME_OFFSET = 1;

  int fd;
  size_t len, siz;
  struct sockaddr_un addr;
  socklen_t socklen;
  int res;

  assert(socket_name);

  fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd < 0) {
    ALOGE_ERRNO("socket");
    goto err_socket;
  }
  if (TEMP_FAILURE_RETRY(fcntl(fd, F_SETFL, O_NONBLOCK)) < 0) {
    ALOGE_ERRNO("fcntl");
    goto err_fcntl;
  }

  len = strlen(socket_name);
  siz = len + 1; /* include trailing '\0' */

  addr.sun_family = AF_UNIX;
  assert(NAME_OFFSET + siz <= sizeof(addr.sun_path));
  memset(addr.sun_path, '\0', NAME_OFFSET); /* abstract socket */
  memcpy(addr.sun_path + NAME_OFFSET, socket_name, siz);

  socklen = offsetof(struct sockaddr_un, sun_path) + NAME_OFFSET + siz;

  res = TEMP_FAILURE_RETRY(connect(fd,
                                   (const struct sockaddr*)&addr,
                                   socklen));
  if (res < 0) {
    ALOGE_ERRNO("connect");
    goto err_connect;
  }

  if (add_fd_to_epoll_loop(fd, EPOLLHUP|EPOLLERR, func, data) < 0)
    goto err_add_fd_to_epoll_loop;

  return fd;
err_add_fd_to_epoll_loop:
err_connect:
err_fcntl:
  if (TEMP_FAILURE_RETRY(close(fd)) < 0)
    ALOGW_ERRNO("close");
err_socket:
  return -1;
}

static enum ioresult
io_fd_event(int fd ATTRIBS(UNUSED), uint32_t events,
            void* data ATTRIBS(UNUSED))
{
  enum ioresult res;

  if ((events & EPOLLERR) || (events & EPOLLHUP)) {
    /* The connection terminated, close and exit. */
    res = IO_EXIT;
  } else {
    ALOGW("unsupported event mask: %u", events);
    res = IO_OK;
  }
  return res;
}

static enum ioresult
init(void* data ATTRIBS(UNUSED))
{
  const struct options* options = data;

  if (connect_socket(options->socket_name, io_fd_event, NULL) < 0)
    return IO_ABORT;

  /* We should have two pending connection request at this point; enough
   * to wake up the daemon on input. Suspending is OK from now on. */
  release_wake_lock(WAKE_LOCK_NAME);

  return IO_OK;
}

static void
uninit(void* data ATTRIBS(UNUSED))
{
  return;
}

int
main(int argc, char* argv[])
{
  static const char DEFAULT_SOCKET_NAME[] = "bluetoothd-snoop";

  static int (* const parse_opt[])(int, char*, struct options*) = {
    ['a'] = parse_opt_a,
    ['h'] = parse_opt_h,
    ['?'] = parse_opt_question_mark
  };

  int res;
  struct options options = {
    .socket_name = DEFAULT_SOCKET_NAME
  };

  /* Guarantee progress until we opened a connection, or exit. */
  acquire_wake_lock(PARTIAL_WAKE_LOCK, WAKE_LOCK_NAME);

  res = 0;

  opterr = 0; /* no default error messages from getopt */

  do {
    int c = getopt(argc, argv, "a:h");

    if (c < 0)
      break; /* end of options */
    else if (c < (ssize_t)ARRAY_LENGTH(parse_opt) && parse_opt[c])
      res = parse_opt[c](c, optarg, &options);
    else
      res = -1;
  } while (!res);

  if (res) /* going to exit */
    release_wake_lock(WAKE_LOCK_NAME);

  if (res > 0)
    exit(EXIT_SUCCESS);
  else if (res < 0)
    exit(EXIT_FAILURE);

  make_daemon();

  if (epoll_loop(init, uninit, &options) < 0)
    goto err_epoll_loop;

  exit(EXIT_SUCCESS);
err_epoll_loop:
  exit(EXIT_FAILURE);
}
