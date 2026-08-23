#!/bin/sh
set -u

umask 077
uid=$(id -u)

fail() {
  printf '%s\n' "mcp-restrictor: $1" >&2
  exit 1
}

private_directory_is_valid() {
  path=$1
  test ! -L "$path" &&
    test -d "$path" &&
    test "$(stat -c %u "$path")" = "$uid" &&
    test "$(stat -c %a "$path")" = "700"
}

prepare_private_directory() {
  path=$1
  if test ! -e "$path" && test ! -L "$path"; then
    mkdir -m 700 "$path" 2>/dev/null || :
  fi
  private_directory_is_valid "$path" || fail "invalid container private directory"
}

validate_private_lock() {
  path=$1
  test ! -L "$path" &&
    test -f "$path" &&
    test "$(stat -c %u "$path")" = "$uid" &&
    test "$(stat -c %a "$path")" = "600"
}

prepare_private_directory "$HOME/.mcp-restrictor"
prepare_private_directory "$HOME/.mcp-restrictor-key"

lock="$HOME/.mcp-restrictor/.container.lock"
if test ! -e "$lock" && test ! -L "$lock"; then
  (set -C; : > "$lock") 2>/dev/null || :
fi
validate_private_lock "$lock" || fail "invalid container lock file"
exec 9<>"$lock"
validate_private_lock "$lock" || fail "invalid container lock file"
lock_identity=$(stat -c '%d:%i' "$lock") || fail "invalid container lock file"
fd_identity=$(stat -Lc '%d:%i' /proc/self/fd/9) || fail "invalid container lock file"
test "$lock_identity" = "$fd_identity" || fail "invalid container lock file"

if ! flock -n 9; then
  fail "state is in use; stop the other container sharing this state and key volume pair"
fi

export MCP_RESTRICTOR_CONTAINER=1
exec mcp-restrictor "$@"
