#!/bin/sh

fkst_profile_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

fkst_profile_owner() {
  if stat -f '%u' "$1" >/dev/null 2>&1; then
    stat -f '%u' "$1"
  else
    stat -c '%u' "$1"
  fi
}

fkst_validate_secure_profile() {
  _fkst_profile_path=$1
  _fkst_profile_required=${2:-0}
  if [ ! -e "$_fkst_profile_path" ]; then
    if [ "$_fkst_profile_required" = "1" ]; then
      echo "error: required profile is missing: $_fkst_profile_path" >&2
      return 1
    fi
    return 3
  fi
  if [ ! -f "$_fkst_profile_path" ] || [ -L "$_fkst_profile_path" ]; then
    echo "error: profile must be a regular non-symlink file: $_fkst_profile_path" >&2
    return 1
  fi
  _fkst_profile_mode=$(fkst_profile_mode "$_fkst_profile_path")
  case "$_fkst_profile_mode" in
    400|600) ;;
    *)
      echo "error: profile must be owner-only (mode 400 or 600): $_fkst_profile_path mode=$_fkst_profile_mode" >&2
      return 1
      ;;
  esac
  _fkst_profile_owner=$(fkst_profile_owner "$_fkst_profile_path")
  if [ "$_fkst_profile_owner" != "$(id -u)" ]; then
    echo "error: profile must be owned by the current user: $_fkst_profile_path" >&2
    return 1
  fi
}

fkst_source_secure_profile() {
  set -a
  # shellcheck disable=SC1090
  . "$1"
  set +a
}

fkst_load_secure_profile() {
  if fkst_validate_secure_profile "$1" "${2:-0}"; then
    fkst_source_secure_profile "$1"
    return
  else
    _fkst_profile_rc=$?
  fi
  [ "$_fkst_profile_rc" = "3" ] && return 0
  return "$_fkst_profile_rc"
}

# Load a trusted .env-style shell profile as defaults. Variables already set by
# the calling process, including explicit empty strings, retain precedence.
fkst_load_secure_profile_defaults() {
  if fkst_validate_secure_profile "$1" "${2:-0}"; then
    :
  else
    _fkst_profile_rc=$?
    [ "$_fkst_profile_rc" = "3" ] && return 0
    return "$_fkst_profile_rc"
  fi

  _fkst_override_names=""
  _fkst_assignment_names=$(LC_ALL=C sed -E -n \
    's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*/\2/p' \
    "$1" | LC_ALL=C sort -u)
  for _fkst_name in $_fkst_assignment_names; do
    eval "_fkst_is_set=\${${_fkst_name}+x}"
    if [ "$_fkst_is_set" = "x" ]; then
      eval "_fkst_value=\${${_fkst_name}-}"
      _fkst_slot="_FKST_PROFILE_OVERRIDE_$$_${_fkst_name}"
      export "$_fkst_slot=$_fkst_value"
      _fkst_override_names="$_fkst_override_names $_fkst_name"
    fi
  done

  fkst_source_secure_profile "$1"

  for _fkst_name in $_fkst_override_names; do
    _fkst_slot="_FKST_PROFILE_OVERRIDE_$$_${_fkst_name}"
    eval "_fkst_value=\${${_fkst_slot}-}"
    export "$_fkst_name=$_fkst_value"
    unset "$_fkst_slot"
  done
}
