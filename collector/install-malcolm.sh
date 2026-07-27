#!/usr/bin/env bash
# Install and configure Malcolm as the collector.
#
# Deliberately drives `docker compose` directly rather than Malcolm's own
# ./scripts/start. Those scripts need Python >= 3.12 and assume a Linux host
# layout. The cost is that a few things ./scripts/start would have done for us
# have to be done explicitly here - see "post-configure fixes" below.
#
# Idempotent: safe to re-run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "${REPO_ROOT}/config.env"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m   %s\n' "$*"; }
warn() { printf '    \033[33mwarn\033[0m %s\n' "$*"; }
die()  { printf '    \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

# Host-side paths as the *Docker engine* must be told to see them.
if [[ "${DOCKER_DESKTOP_WINDOWS}" == "true" ]]; then
  MALCOLM_MOUNT="$MALCOLM_DIR_WIN"
  DATA_MOUNT="$DATA_ROOT_WIN"
else
  MALCOLM_MOUNT="$MALCOLM_DIR"
  DATA_MOUNT="$DATA_ROOT"
fi

# ghcr.io serves these images anonymously, but a stale/insufficient credential
# in ~/.docker/config.json makes the daemon send it anyway and get "denied" -
# which reads exactly like the image not existing. Pull with an empty config.
ANON_CFG=/tmp/dockercfg-anon
mkdir -p "$ANON_CFG"; echo '{"auths":{}}' > "${ANON_CFG}/config.json"
dpull() { DOCKER_CONFIG="$ANON_CFG" docker pull "$@"; }

# ---------------------------------------------------------------------------
say "Preflight"

command -v docker >/dev/null || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin not found"
ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)"

MMC=$(docker run --rm --privileged alpine sysctl -n vm.max_map_count 2>/dev/null || echo 0)
[[ "${MMC:-0}" -ge 262144 ]] && ok "vm.max_map_count=${MMC}" \
  || warn "vm.max_map_count=${MMC} (<262144) - OpenSearch may refuse to start"

AVAIL_MB=$(free -m 2>/dev/null | awk '/^Mem:/{print $7}')
if [[ -n "${AVAIL_MB:-}" ]]; then
  HEAP_MB=$(( ${OPENSEARCH_HEAP%g} * 1024 + ${LOGSTASH_HEAP%m} ))
  ok "available RAM ${AVAIL_MB}MB, configured JVM heap ${HEAP_MB}MB"
  (( AVAIL_MB < HEAP_MB + 3072 )) && warn "less than 3GB headroom beyond JVM heap - expect swapping"
fi

# ---------------------------------------------------------------------------
say "Fetching Malcolm ${MALCOLM_VERSION}"

if [[ -d "${MALCOLM_DIR}/.git" ]]; then
  ok "already present at ${MALCOLM_DIR}"
else
  git clone --depth 1 --branch "$MALCOLM_VERSION" \
    https://github.com/cisagov/Malcolm.git "$MALCOLM_DIR" 2>&1 | tail -1
  ok "cloned to ${MALCOLM_DIR}"
fi
cd "$MALCOLM_DIR"

say "Building Python 3.13 helper"
docker build -q -t malcolm-helper -f "${REPO_ROOT}/collector/helper.Dockerfile" \
  "${REPO_ROOT}/collector" >/dev/null
ok "malcolm-helper built"

# auth_setup refuses to run as root, and on a Windows bind mount the tree is
# root-owned 0755 so uid 1000 cannot write to it either. Stage the tree in a
# docker volume we can chown, run there, then copy the results back.
run_in_stage() {
  docker volume create malcolm-work >/dev/null
  docker run --rm -v malcolm-work:/work -v "${MALCOLM_MOUNT}:/src" alpine \
    sh -c 'cp -a /src/. /work/ && chown -R 1000:1000 /work'
  docker run --rm -i --user 1000:1000 --group-add 0 \
    -e HOME=/home/malcolm -e USER=malcolm -e LOGNAME=malcolm \
    -v malcolm-work:/malcolm -v /var/run/docker.sock:/var/run/docker.sock \
    -w /malcolm malcolm-helper "$@"
  docker run --rm -v malcolm-work:/work -v "${MALCOLM_MOUNT}:/dst" alpine \
    sh -c 'cp -a /work/. /dst/'
  docker volume rm -f malcolm-work >/dev/null
}

# ---------------------------------------------------------------------------
say "Generating Malcolm configuration"

if [[ -f "${MALCOLM_DIR}/config/process.env" ]]; then
  ok "config/ already generated - skipping configure"
else
  docker run --rm -i -v "${MALCOLM_MOUNT}:/malcolm" -w /malcolm malcolm-helper \
    python3 ./scripts/configure -c --non-interactive --defaults --skip-splash 2>&1 | tail -3
  ok "config/*.env written"
fi

say "Configuring authentication"

mkdir -p "${REPO_ROOT}/keys"; chmod 700 "${REPO_ROOT}/keys"
PWFILE="${REPO_ROOT}/keys/malcolm_pw"
if [[ ! -s "$PWFILE" ]]; then
  python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print(''.join(secrets.choice(a) for _ in range(24)))" > "$PWFILE"
  chmod 600 "$PWFILE"
fi
PW=$(cat "$PWFILE")

if [[ -s "${MALCOLM_DIR}/nginx/htpasswd" ]]; then
  ok "auth already configured - skipping (delete nginx/htpasswd to redo)"
else
  ARK=$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print(''.join(secrets.choice(a) for _ in range(32)))")
  H6=$(docker run --rm malcolm-helper openssl passwd -6 "$PW" | tr -d '\r\n')
  HB=$(printf '%s' "$PW" | docker run --rm -i malcolm-helper \
        python3 -c "import bcrypt,sys; print(bcrypt.hashpw(sys.stdin.read().strip().encode(), bcrypt.gensalt(rounds=12)).decode())" | tr -d '\r\n')
  run_in_stage python3 ./scripts/auth_setup --auth-noninteractive \
    --auth-method basic --auth-admin-username "$MALCOLM_ADMIN_USER" \
    --auth-admin-password-openssl "$H6" --auth-admin-password-htpasswd "$HB" \
    --auth-arkime-password "$ARK" \
    --auth-generate-webcerts true --auth-generate-fwcerts true \
    --auth-generate-netbox-passwords true --auth-generate-valkey-password true \
    --auth-generate-postgres-password true --auth-generate-opensearch-internal-creds true \
    --auth-generate-keycloak-db-password true
  ok "credentials, certs and htpasswd generated"
fi

# ---------------------------------------------------------------------------
say "Post-configure fixes"

cd "$MALCOLM_DIR"

# ./scripts/start touches these; starting via docker compose does not. Without
# them Zeek hits `can't open .../site/custom/__load__.zeek` and dies on EVERY
# pcap while its container still reports healthy - so the pipeline looks fine
# and simply produces no Zeek logs at all.
touch zeek/intel/__load__.zeek zeek/custom/__load__.zeek
ok "zeek __load__.zeek stubs present"

# Directories Malcolm expects to exist. Bind mounts use create_host_path:false,
# so a missing one is a hard container failure rather than an auto-mkdir.
mkdir -p netbox/media postgres valkey opensearch opensearch-backup \
         pcap/upload pcap/processed zeek-logs/{current,processed,upload,live,extract_files}
touch opensearch/opensearch.keystore nginx/nginx_ldap.conf .opensearch.secondary.curlrc
chmod 600 .opensearch.secondary.curlrc
ok "expected paths created"

cfg_set() { # cfg_set FILE KEY VALUE
  local f="config/$1" k="$2" v="$3"
  grep -q "^${k}=" "$f" 2>/dev/null && sed -i "s|^${k}=.*|${k}=${v}|" "$f"
}

# Malcolm's configure records the UID it ran as - which was root, inside the
# helper container. The entrypoint then runs `usermod -u 0`, which tries to
# chown Arkime's home; that home contains bind mounts, the chown fails, and
# Arkime exits 12. Every image ships uid 1000.
cfg_set process.env PUID 1000
cfg_set process.env PGID 1000
ok "PUID/PGID=1000"

# inotify events do not cross Docker Desktop's Windows file sharing. With the
# native watcher the pipeline sits idle forever and ingests nothing.
if [[ "${DOCKER_DESKTOP_WINDOWS}" == "true" ]]; then
  cfg_set upload-common.env PCAP_PIPELINE_POLLING true
  cfg_set filebeat.env      FILEBEAT_WATCHER_POLLING true
  ok "file watchers set to polling (inotify does not work on this mount)"
fi

sed -i "s|-Xmx[0-9]*[gm] -Xms[0-9]*[gm]|-Xmx${OPENSEARCH_HEAP} -Xms${OPENSEARCH_HEAP}|" config/opensearch.env
sed -i "s|-Xmx[0-9]*[gm] -Xms[0-9]*[gm]|-Xmx${LOGSTASH_HEAP} -Xms${LOGSTASH_HEAP}|" config/logstash.env
ok "heaps: opensearch=${OPENSEARCH_HEAP} logstash=${LOGSTASH_HEAP}"

cfg_set arkime.env MANAGE_PCAP_FILES true
cfg_set arkime.env ARKIME_FREESPACEG "$ARKIME_FREESPACEG"
ok "PCAP retention: prune below ${ARKIME_FREESPACEG}GB free"

# ---------------------------------------------------------------------------
say "Preparing data root"

docker run --rm -v "${DATA_MOUNT}:/d" alpine sh -c '
  mkdir -p /d/pcap/upload /d/pcap/processed /d/pcap/staging \
           /d/opensearch /d/opensearch-backup /d/zeek-logs/extract_files/filescan \
           /d/zeek-logs/current /d/zeek-logs/processed /d/zeek-logs/upload /d/zeek-logs/live \
           /d/suricata-logs /d/filescan-logs /d/postgres /d/valkey /d/netbox/media
  touch /d/opensearch/opensearch.keystore'
ok "data directories created under ${DATA_ROOT}"

say "Rewriting compose bind mounts"
python3 "${REPO_ROOT}/collector/patch-compose.py" docker-compose.yml \
  --malcolm-base "$MALCOLM_MOUNT" --data-base "$DATA_MOUNT"

# Containers run as uid 1000; anything they must write has to be owned by it.
# Do this AFTER auth_setup, which writes as a different uid.
docker run --rm -v "${DATA_MOUNT}:/d" alpine chown -R 1000:1000 /d
docker run --rm -v "${MALCOLM_MOUNT}:/m" alpine sh -c 'chown -R 1000:1000 /m 2>/dev/null || true'
ok "ownership set to 1000:1000"

docker compose --profile malcolm config >/dev/null || die "compose file is invalid after patching"
ok "compose validates"

# ---------------------------------------------------------------------------
say "Pulling images (anonymous)"
grep -oE "ghcr\.io/idaholab/malcolm/[a-z0-9-]+:[0-9.]+" docker-compose.yml | sort -u \
  | xargs -P 4 -I{} sh -c "DOCKER_CONFIG=${ANON_CFG} docker pull {} >/dev/null 2>&1 && echo '    ok   {}' || echo '    FAIL {}'"

if [[ "${OSD_ENHANCED_DISCOVER:-false}" == "true" ]]; then
  say "Enabling Dashboards enhanced Discover"

  # The dashboards entrypoint copies opensearch_dashboards.orig.yml over the
  # live config on every start, so the ORIGINAL is the only durable place to
  # set options - edits to the final file are silently undone on restart.
  OSD_IMAGE=$(grep -oE "ghcr\.io/idaholab/malcolm/dashboards:[0-9.]+" docker-compose.yml | head -1)
  mkdir -p dashboards/config
  ORIG=dashboards/config/opensearch_dashboards.orig.yml
  [[ -s "$ORIG" ]] || docker run --rm --entrypoint cat "$OSD_IMAGE" \
      /usr/share/opensearch-dashboards/config/opensearch_dashboards.orig.yml > "$ORIG"

  if ! grep -q '^explore.enabled' "$ORIG"; then
    cat >> "$ORIG" <<'YML'

# --- Enhanced Discover experience (er4-malcolm-nsm) --------------------------
data_source.enabled: true
workspace.enabled: true
explore.enabled: true
YML
  fi

  cat > docker-compose.override.yml <<YML
# Local overrides layered on Malcolm's docker-compose.yml.
services:
  dashboards:
    volumes:
      - type: bind
        bind:
          create_host_path: false
        source: ${MALCOLM_MOUNT}/dashboards/config/opensearch_dashboards.orig.yml
        target: /usr/share/opensearch-dashboards/config/opensearch_dashboards.orig.yml
        read_only: true
YML
  ok "workspace / data_source / explore enabled"
fi

say "Starting Malcolm"
docker compose --profile malcolm up -d 2>&1 | tail -3

cat <<EOF

$(printf '\033[1m==> Malcolm starting.\033[0m')
    UI:       https://${COLLECTOR_IP}/
    User:     ${MALCOLM_ADMIN_USER}
    Password: ${PW}   (also in ${PWFILE})

    First start takes several minutes: OpenSearch initialises its security
    index and Arkime builds a fresh database before nginx can proxy them.
    Watch with:  cd ${MALCOLM_DIR} && docker compose ps
EOF
