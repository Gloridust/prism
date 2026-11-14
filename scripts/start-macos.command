#!/bin/bash
# Double-click launcher for macOS (work-from-home staff).
# Put this file next to `prism-client` and `client.json`, then:
#   chmod +x start-macos.command   (first time, in Terminal)
# Double-click it. The control panel opens in your browser.
cd "$(dirname "$0")" || exit 1
open "http://127.0.0.1:9797" 2>/dev/null &
# Setting the system proxy may ask for your password.
exec ./prism-client -c ./client.json
