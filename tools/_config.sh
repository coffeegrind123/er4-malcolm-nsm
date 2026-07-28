# Shared config.env loader for the bash tools. Source it, do not execute it:
#
#     . "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
#
# config.env.example says "Every script sources this file", and for a long time
# most of them did not - tools/watchdog carried its own hardcoded //d/malcolm-data
# defaults and ignored DATA_ROOT entirely, so relocating the data root moved the
# data and left the watchdog checking the old path, reporting a healthy pipeline
# while watching a directory nothing writes to. tools/investigate had the same gap
# and it made OBSERVER_DESTS inert.
#
# It really does have to SOURCE the file rather than parse it. config.env contains
# shell references - MALCOLM_DIR="${HOME}/malcolm" - so a literal key=value reader
# exports the string ${HOME}/malcolm and every path built from it fails with a
# "No such file or directory" naming a variable that was never expanded.
#
# EXISTING ENVIRONMENT WINS. A bare `source` overwrites variables deliberately set
# for one run, which would break `MEM_WARN_MB=99999 tools/watchdog` and every other
# one-off override - including the ones used to prove a check fires at all. So
# snapshot what was already set, source, then put the snapshot back.
_load_config_env() {
  local root cfg key line
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  cfg="${root}/config.env"
  [[ -f "$cfg" ]] || return 0

  # Remember pre-set values so sourcing cannot clobber an intentional override.
  local -a preset_keys=() preset_vals=()
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ -n "${!key+x}" ]]; then
      preset_keys+=("$key")
      preset_vals+=("${!key}")
    fi
  done < "$cfg"

  set -a
  # shellcheck disable=SC1090
  . "$cfg"
  set +a

  local i
  for i in "${!preset_keys[@]}"; do
    export "${preset_keys[$i]}=${preset_vals[$i]}"
  done
}
_load_config_env

# Derive the mount paths the tools use from DATA_ROOT_WIN when config.env supplies
# it, so a relocated data root reaches every tool instead of only the two that
# happened to read it.
if [[ -n "${DATA_ROOT_WIN:-}" ]]; then
  : "${PCAP_MOUNT:=${DATA_ROOT_WIN}/pcap}"
  : "${ZEEK_MOUNT:=${DATA_ROOT_WIN}/zeek-logs}"
fi

# config.env calls it MALCOLM_ADMIN_USER; the API tools read MALCOLM_USER. Same
# account, two names, so setting it in config.env silently did nothing to them.
if [[ -n "${MALCOLM_ADMIN_USER:-}" ]]; then
  : "${MALCOLM_USER:=${MALCOLM_ADMIN_USER}}"
fi
