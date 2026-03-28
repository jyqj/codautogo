#!/bin/sh
set -eu

mkdir -p /app/logs
exec /usr/local/bin/codex "$@" 2>>/app/logs/error.log
