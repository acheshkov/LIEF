/* Copyright 2017 - 2025 R. Thomas
 * Copyright 2017 - 2025 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "LoadCommand.hpp"

namespace LIEF {
namespace MachO {
void init_c_commands(Macho_Binary_t* c_binary, Binary* binary) {
  Binary::it_commands commands = binary->commands();

  c_binary->commands = static_cast<Macho_Command_t**>(
      malloc((commands.size() + 1) * sizeof(Macho_Command_t*)));
  if (!c_binary->commands) {
    return;
  }

  for (size_t i = 0; i < commands.size(); ++i) {
    LoadCommand& cmd = commands[i];

    Macho_Command_t* c_cmd = static_cast<Macho_Command_t*>(malloc(sizeof(Macho_Command_t)));
    if (!c_cmd) {
      continue;
    }

    const span<const uint8_t> cmd_content = cmd.data();
    uint8_t* content = static_cast<uint8_t*>(malloc(cmd_content.size() * sizeof(uint8_t)));
    if (!content) {
      free(c_cmd);
      continue;
    }

    std::copy(
        std::begin(cmd_content),
        std::end(cmd_content),
        content);

    c_cmd->command = static_cast<enum LIEF_MACHO_LOAD_COMMAND_TYPES>(cmd.command());
    c_cmd->size    = cmd.size();
    c_cmd->data    = content;
    c_cmd->offset  = cmd.command_offset();

    c_binary->commands[i] = c_cmd;
  }

  c_binary->commands[commands.size()] = nullptr;
}




void destroy_commands(Macho_Binary_t* c_binary) {
  Macho_Command_t **commands = c_binary->commands;
  for (size_t idx = 0; commands[idx] != nullptr; ++idx) {
    free(commands[idx]->data);
    free(commands[idx]);
  }
  free(c_binary->commands);

}

}
}


