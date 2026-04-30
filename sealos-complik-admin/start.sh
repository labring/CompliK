#!/usr/bin/env bash

set -euo pipefail

PORT=8080
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT_DIR"

pids="$(lsof -ti tcp:${PORT} -sTCP:LISTEN || true)"
if [ -n "$pids" ]; then
	echo "Stopping processes on port ${PORT}: ${pids}"
	kill ${pids}

	sleep 1

	remaining_pids="$(lsof -ti tcp:${PORT} -sTCP:LISTEN || true)"
	if [ -n "$remaining_pids" ]; then
		echo "Force killing remaining processes on port ${PORT}: ${remaining_pids}"
		kill -9 ${remaining_pids}
	fi
else
	echo "Port ${PORT} is free"
fi

echo "Starting app..."
exec go run ./cmd
