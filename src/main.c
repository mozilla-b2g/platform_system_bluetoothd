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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <hardware_legacy/power.h>
#include <fdio/loop.h>
#include <fdio/task.h>
#include "compiler.h"
#include "log.h"
#include "wakelock.h"
#include "bt-io.h"

#define ARRAY_LENGTH(_array) \
  ( sizeof(_array) / sizeof((_array)[0]) )

struct options {
  const char* socket_name;
};

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
  printf("Usage: bluetoothd [OPTION]\n"
         "Wraps Bluedroid behind a network protocol\n"
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

static enum ioresult
init(void* data ATTRIBS(UNUSED))
{
  const struct options* options = data;

  if (init_task_queue() < 0)
    goto err_init_task_queue;

  if (init_bt_io(options->socket_name) < 0)
    goto err_init_bt_io;

  /* We should have two pending connection request at this point; enough
   * to wake up the daemon on input. Suspending is OK from now on. */
  release_wake_lock(WAKE_LOCK_NAME);

  return IO_OK;
err_init_bt_io:
  uninit_task_queue();
err_init_task_queue:
  release_wake_lock(WAKE_LOCK_NAME);
  return IO_ABORT;
}

static void
uninit(void* data ATTRIBS(UNUSED))
{
  uninit_bt_io();
  uninit_task_queue();
}

int
main(int argc, char* argv[])
{
  static const char DEFAULT_SOCKET_NAME[] = "bluetoothd";

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
