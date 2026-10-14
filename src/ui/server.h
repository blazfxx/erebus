#pragma once
#include "cli/session.h"

namespace er {

// Starts the local web UI. Blocks until the process is interrupted.
// watchPid > 0: shut down automatically when that process exits (used by the macOS app).
int serveUi(Session& s, const std::string& host, int port, bool openBrowser, int watchPid = 0);

}  // namespace er
