#pragma once
#include <ostream>
#include <string>
#include <vector>

#include "cli/session.h"

namespace er {

// Executes one command line (already tokenized). Returns false for "quit".
bool runCommand(Session& s, const std::vector<std::string>& args, std::ostream& os);

std::vector<std::string> tokenize(const std::string& line);

}  // namespace er
