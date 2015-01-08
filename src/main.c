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

#include <stdlib.h>
#include <unistd.h>
#include <fdio/loop.h>
#include <fdio/task.h>
#include "compiler.h"
#include "bt-io.h"

struct options {
  const char* socket_name;
};

static enum ioresult
init(void* data ATTRIBS(UNUSED))
{
  const struct options* options = data;

  if (init_task_queue() < 0)
    goto err_init_task_queue;

  if (init_bt_io(options->socket_name) < 0)
    goto err_init_bt_io;

  return IO_OK;
err_init_bt_io:
  uninit_task_queue();
err_init_task_queue:
  return IO_ABORT;
}

static void
uninit(void* data ATTRIBS(UNUSED))
{
  uninit_bt_io();
  uninit_task_queue();
}

int
main(int argc ATTRIBS(UNUSED), const char* argv[] ATTRIBS(UNUSED))
{
  static const char DEFAULT_SOCKET_NAME[] = "bluetoothd";

  struct options options = {
    .socket_name = DEFAULT_SOCKET_NAME
  };

  if (epoll_loop(init, uninit, &options) < 0)
    goto err_epoll_loop;

  exit(EXIT_SUCCESS);
err_epoll_loop:
  exit(EXIT_FAILURE);
}
