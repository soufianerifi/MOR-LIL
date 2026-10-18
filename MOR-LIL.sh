#!/usr/bin/env bash
# =============================================================================
# Finixo Gate 3.2.6  —  audit6: port-wait awk, CC batch trap, stick-table, cert domain, paths 600, purge bin
#
# Architecture (locked-down):
#   Client ──TLS──▶ Nginx :443/:80  ──path route──▶ Xray 127.0.0.1 (security:none)
#                                              └──▶ SSH-WS bridge ──▶ sshd (tunnel-only)
#
# Protocols: VLESS-WS | VMess-WS | Trojan-WS | Shadowsocks-2022-WS | SSH-WS
# OS: Ubuntu 22.04 / 24.04, Debian 12   (x86_64, arm64)
#
# 3.1.0 GOLDEN TITAN + HAProxy edge:
#   · HAProxy public 80/443 (TLS, path route, tunnel 24h); Nginx localhost site+ACME
#   · Stable hidden paths /cdn/assets/js/*.chunk.js (one per protocol)
#   · Safe binds: TFO/IPv6 only when available; haproxy -c verified
# 3.0.0 GOLDEN TITAN:
#   · Radiant gold / multi-color TUI (truecolor + 256 fallback)
#   · Stronger kernel profile: BBR + larger BDP windows + tcp_fastopen + lower latency
#   · Nginx: higher SSL session cache, longer keepalive, reuseport already on
#   · Online counter: same exact Stats API + ghost filter; menu header stays live
#   · 24/7: watchdog + worker_shutdown_timeout + socket keepalive unchanged & hardened
# 2.8.4: live monitor REMOVED (key m, `finixo monitor`, the SSH-WS bridge counters and the watchdog "online for" file that only fed it)
#        Devices stay: Users screen + `finixo devices`
# 2.8.3: DEVICES per account (estimate = client networks online at the same time, sampled every minute by the watchdog timer)
#        Users screen · `finixo devices` · limit only MARKS (finixo devices limit N)
# 2.8.2: menu 4 = Users (name, online/offline, entered, left, data used, expiry; persistent) · Control "Extend time"
# 2.8.0: Stability: Xray connection policy + exact online counter applied by repair / upgrade prompt, kernel tuning applied by
#        repair, nginx keepalive tuning, systemd restart drop-ins · watchdog (finixo watchdog) restarts only hung services
#        menu RAM/CPU rows refresh every tick
#        18 audit fixes (see the change list shipped with this file)
# 2.7.0: Connection Control wizard (action > protocol > user, multi-select, renew, reset key, purge, traffic)
#        Protocol menus only add/list · exact counter hardened (ghost filter, unique names, shared-name flag)
#        repair keeps Nginx+Xray paths in sync · SSH Enable fixed · banner inside Match · safer shell migration
#        optional Let's Encrypt e-mail (FINIXO_LE_EMAIL or prompt)
# 2.6.4: FIXED short WS paths again (/vless-ws /vmess-ws /trojan-ws /ss-ws /ssh-ws)
#        — random paths broke HTTP Custom / remote proxy clients
# 2.6.3: red radiant UI · clean Connection Control · delete y/n · tighter menus
# 2.6.2: Accurate session kill on disable/delete (restart after rmu) · no false "sessions killed"
#        Remove "only user" delete refuse · drop duplicate show-admin case · honesty fixes
# 2.6.1: SSH-WS user control (disable/lock · enable · kick · delete) in Connection Control + SSH menu
# 2.6.1: EXACT live online counter (menu header + Connection Control + dashboard):
#        Xray Stats API (statsUserOnline + trustedXForwardedFor) + live sshd sessions
# 2.6.0: Audit fixes - nft resolver exception + nftables pkg, purge timer always on,
#        disabled-user expiry, batched restart on expiry, Trojan allowInsecure only self-signed,
#        real --force-renewal, octal-safe durations, live online counter, menu numbers, hardening
# 2.5.6: One fixed path per protocol (/vless-ws /vmess-ws /trojan-ws /ss-ws /ssh-ws)
# 2.5.5: SSH path fixed /ssh-ws + clear HTTP Custom payload (path must match)
# 2.5.4: E2E self-test skips when no users (zero-default install)
# 2.5.3: SSH-WS bridge lenient + correct payload (Sec-WebSocket-Key); zero default users
# 2.5.2: WS 101 fix for remote proxy/CDN (Connection upgrade hardcoded)
# 2.5.1: No embedded SSH admin/backdoor — OS logins untouched
# 2.5.0: Connection control (disable/enable/kick/delete) · session-safe
# 2.4.0: Dedicated admin (no touch others) · dokodemo API · research-grade stability
# 2.3.0: Precise expiry (days+hours) · hot-add API · accurate online counter
#        Auto-purge timer · stronger UI · max stability for selling configs
# 2.1.0: New full-screen TUI (arrows/hjkl/tap/wheel/1-20) · Xray install fix
#        (SIGPIPE under pipefail) · tunnel verdict after install
# 2.0.0: Rebrand Finixo · max-throughput Nginx WS · BBR+buffer harden
#        Stronger 101 upgrade path · Iron Test · Titan UI colors
#        Locked client endpoint (no Remote/SNI/Host editing)
# Public surface: 80 + 443 (+ SSH). All Xray/bridge ports bind 127.0.0.1 only.
# Command: finixo | install | test | deep-test | strict-test | harden | status
# =============================================================================
export LC_ALL=C.UTF-8 2>/dev/null || true
set -uo pipefail
umask 022
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

VERSION="3.2.6"
CONF_DIR=/etc/finixo
ENV_FILE=$CONF_DIR/paths.env
EXPIRY_DB=$CONF_DIR/expiry.db
DISABLED_DB=$CONF_DIR/disabled.db
IP_FILE=$CONF_DIR/ip
TLS_DIR=$CONF_DIR/tls
TLS_CRT=$TLS_DIR/server.crt
TLS_KEY=$TLS_DIR/server.key
XRAY_BIN=/usr/local/bin/xray
XRAY_DIR=/usr/local/etc/xray
XRAY_CFG=$XRAY_DIR/config.json
XRAY_ASSET=/usr/local/share/xray
XRAY_LOG=/var/log/xray
BRIDGE_DIR=/usr/local/lib/finixo
BRIDGE=$BRIDGE_DIR/ssh-ws-bridge.py
HOLD=$BRIDGE_DIR/ssh-hold.sh
NGX_CONF=/etc/nginx/conf.d/finixo.conf
NGX_RATE=/etc/nginx/conf.d/00-finixo-rate.conf
NGX_PERF=/etc/nginx/conf.d/00-finixo-perf.conf
NGX_STEALTH=/etc/nginx/conf.d/00-finixo-stealth.conf
NGX_SYSD=/etc/systemd/system/nginx.service.d/finixo.conf
NGX_WS=/etc/nginx/finixo-ws.inc
HAP_CFG=/etc/haproxy/haproxy.cfg
HAP_PEM=$TLS_DIR/haproxy.pem
HAP_SYSD=/etc/systemd/system/haproxy.service.d/finixo.conf
# Edge / IPv6: remember if the operator set them in the environment BEFORE defaults
# (so load_conf does not clobber `FINIXO_EDGE=nginx write_nginx_full` or CLI exports).
_FINIXO_EDGE_EXPLICIT=0
_FINIXO_IPV6_EXPLICIT=0
[ -n "${FINIXO_EDGE+x}" ] && _FINIXO_EDGE_EXPLICIT=1
[ -n "${FINIXO_DISABLE_IPV6+x}" ] && _FINIXO_IPV6_EXPLICIT=1
# Edge: haproxy = public 80/443 via HAProxy (fast), nginx = classic Nginx-only public bind
FINIXO_EDGE=${FINIXO_EDGE:-haproxy}
# 1 = disable IPv6 stack on host (sysctl + no [::] binds). 0 = keep IPv6.
FINIXO_DISABLE_IPV6=${FINIXO_DISABLE_IPV6:-1}
SITE_ROOT=/var/www/finixo-site
SSH_GROUP=tunnel-only
SSH_DROPIN=/etc/ssh/sshd_config.d/00-finixo.conf
SSH_LEGACY_DROPIN=/etc/ssh/sshd_config.d/finixo.conf
SSH_INCLUDE_MARKER=$CONF_DIR/ssh-include-added
BANNER_FILE=$CONF_DIR/ssh-banner.txt
BANNER_CONF=$CONF_DIR/banner.conf
DEV_DB=$CONF_DIR/devices.json
DEV_LIMIT_FILE=$CONF_DIR/max-devices
DEV_MINGAP=45
BIN_LINK=/usr/local/bin/finixo
LOCK_DIR=/run/finixo
NGINX_DEFAULT_BACKUP=$CONF_DIR/backups/nginx-default
STATE_BACKUP_DIR=$CONF_DIR/backups/state

WORK_DIR=""
E2E_PID=""
FINIXO_INSTALL_ACTIVE=0
FINIXO_LOCK_HELD=0
FINIXO_WAS_INSTALLED=0
FINIXO_STATE_BACKUP=0

SERVER_ADDR=""
SERVER_IP=""
REMOTE_PROXY=""
CLIENT_SNI=""
CLIENT_HOST=""
CLIENT_SEC=auto     # auto | tls | none
CLIENT_PIN=auto     # auto | yes | no
REMOTE_PROXY_HOST=""
REMOTE_PROXY_PORT=443
WSP_VLESS=""; WSP_VMESS=""; WSP_TROJAN=""; WSP_SS=""; WSP_SSH=""
DOMAIN=""

P_VLESS=10000
P_VMESS=10001
P_TROJAN=10002
P_SS=10003
P_SSHWS=9022
XRAY_API_PORT=10085
XRAY_API_TAG=api
WS_ACCESS_LOG=/var/log/nginx/finixo-ws.log

# Tunables set in the environment win over the values saved in paths.env.
ENV_OVERRIDE=""
for _k in SSH_MAXSTARTUPS SSH_TCP_FORWARDING NGX_LIMIT_CONN NGX_LIMIT_RATE NGX_LIMIT_BURST FINIXO_EDGE FINIXO_DISABLE_IPV6 FINIXO_REMOTE_PROXY FINIXO_SNI FINIXO_HOST; do
  if [ -n "${!_k:-}" ]; then ENV_OVERRIDE="$ENV_OVERRIDE $_k "; fi
done
unset _k
SSH_MAXSTARTUPS=${SSH_MAXSTARTUPS:-100:30:200}
SSH_TCP_FORWARDING=${SSH_TCP_FORWARDING:-local}
NGX_LIMIT_CONN=${NGX_LIMIT_CONN:-0}
NGX_LIMIT_RATE=${NGX_LIMIT_RATE:-0}
NGX_LIMIT_BURST=${NGX_LIMIT_BURST:-0}
SS_METHOD=${SS_METHOD:-2022-blake3-aes-256-gcm}

export XRAY_LOCATION_ASSET=$XRAY_ASSET

# ----------------------------------------------------------------------------
# UI helpers
# ----------------------------------------------------------------------------
R=""; G=""; Y=""; C=""; W=""; D=""; N=""
BW=66
STEP_N=0
STEP_T=11

# Colour mode:  none = not a terminal / NO_COLOR / TERM=dumb · 256 = default · true = 24-bit, only when the
# terminal announces it (COLORTERM=truecolor|24bit or a *-direct / *truecolor* TERM). FINIXO_COLOR=256|true|none forces it.
FINIXO_CMODE=none
detect_color_mode() {
  FINIXO_CMODE=none
  [ -t 1 ] || return 0
  [ -z "${NO_COLOR:-}" ] || return 0
  [ "${TERM:-dumb}" != dumb ] || return 0
  case "${FINIXO_COLOR:-auto}" in
    none|off|0) return 0 ;;
    256) FINIXO_CMODE=256; return 0 ;;
    true|truecolor|24bit) FINIXO_CMODE=true; return 0 ;;
  esac
  case "${COLORTERM:-}" in truecolor|24bit) FINIXO_CMODE=true; return 0 ;; esac
  case "${TERM:-}" in *-direct|*truecolor*|*24bit*) FINIXO_CMODE=true; return 0 ;; esac
  FINIXO_CMODE=256
}
fg_rgb() {   # r g b -> $FG : 24-bit escape, or the nearest colour of the 256-colour cube
  if [ "$FINIXO_CMODE" = true ]; then FG=$'\e[38;2;'"$1;$2;$3"m
  else FG=$'\e[38;5;'$((16 + 36 * (($1 * 5 + 127) / 255) + 6 * (($2 * 5 + 127) / 255) + (($3 * 5 + 127) / 255)))m; fi
}
setup_colors() {
  detect_color_mode
  if [ "$FINIXO_CMODE" != none ]; then
    # GOLDEN TITAN palette — metallic gold accent + rich support colours
    fg_rgb 255 70 90;    R=$FG        # error / danger
    fg_rgb 50 220 140;   G=$FG        # success emerald
    fg_rgb 255 200 60;   Y=$FG        # amber warning
    fg_rgb 255 200 50;   C=$FG        # main accent — radiant gold
    fg_rgb 255 248 230;  W=$'\e[1m'$FG  # warm ivory bold
    fg_rgb 180 150 90;   D=$FG        # muted bronze
    fg_rgb 120 200 255;  BL=$FG       # sky info
    fg_rgb 200 140 255;  P=$FG        # soft violet
    B=$'\e[1m'
    N=$'\e[0m'
    ACC=$C
  else
    R= G= Y= C= W= D= BL= P= B= N= ACC=
  fi
}
setup_colors

info() { printf '%s  ▸%s %s\n' "$C" "$N" "$*"; }
ok()   { printf '%s  ✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s  !%s %s\n' "$Y" "$N" "$*"; }
err()  { printf '%s  ✗%s %s\n' "$R" "$N" "$*" >&2; }
die()  { err "$*"; exit 1; }

step() {
  STEP_N=$((STEP_N+1))
  printf '\n%s[%d/%d]%s %s%s%s\n' "$C" "$STEP_N" "$STEP_T" "$N" "$W" "$*" "$N"
}

# verify_cmd "label" command...  — run check; die with label on failure
verify_cmd() {
  local label=$1; shift
  if "$@"; then ok "verify: $label"; return 0; fi
  die "verify failed: $label"
}

# verify after each install phase
verify_packages() {
  local bin
  for bin in curl openssl nginx python3 jq ss ufw; do
    command -v "$bin" >/dev/null 2>&1 || die "verify packages: missing $bin"
  done
  ok "verify: required packages present"
}

verify_certificate() {
  [ -f "$TLS_CRT" ] && [ -f "$TLS_KEY" ] || die "verify cert: files missing"
  openssl x509 -in "$TLS_CRT" -noout >/dev/null 2>&1 || die "verify cert: not a valid certificate"
  openssl pkey -in "$TLS_KEY" -noout >/dev/null 2>&1 || die "verify cert: not a valid private key"
  local pc pk
  pc=$(openssl x509 -in "$TLS_CRT" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')
  pk=$(openssl pkey -in "$TLS_KEY" -pubout 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')
  [ -n "$pc" ] && [ "$pc" = "$pk" ] || die "verify cert: certificate/key mismatch"
  [ "$(stat -c '%a' "$TLS_KEY" 2>/dev/null)" = 600 ] || chmod 600 "$TLS_KEY" 2>/dev/null || true
  ok "verify: TLS certificate and key match"
}

verify_xray_binary() {
  [ -x "$XRAY_BIN" ] || die "verify xray: binary not executable at $XRAY_BIN"
  "$XRAY_BIN" version >/dev/null 2>&1 || die "verify xray: binary does not run"
  ok "verify: Xray binary OK ($(xray_ver_line | awk '{print $2}'))"
}

verify_xray_running() {
  systemctl is-active --quiet xray || die "verify xray: service not active"
  validate_xray_config_file "$XRAY_CFG" || die "verify xray: config invalid"
  local tag
  for tag in vless-ws vmess-ws trojan-ws ss-ws; do
    jq -e --arg t "$tag" '.inbounds[]|select(.tag==$t)|select(.listen=="127.0.0.1")' "$XRAY_CFG" >/dev/null 2>&1 \
      || die "verify xray: inbound $tag missing or not on 127.0.0.1"
  done
  ok "verify: Xray running with localhost inbounds"
}

verify_ssh_bridge() {
  systemctl is-active --quiet finixo-ssh-ws || die "verify bridge: finixo-ssh-ws not active"
  [ -x "$BRIDGE" ] || die "verify bridge: script missing"
  [ -x "$HOLD" ] || die "verify bridge: hold script missing"
  [ -f "$SSH_DROPIN" ] || die "verify bridge: sshd drop-in missing"
  ok "verify: SSH-WS bridge and tunnel-only policy"
}

verify_nginx() {
  systemctl is-active --quiet nginx || die "verify nginx: service not active"
  nginx -t >/dev/null 2>&1 || die "verify nginx: configuration invalid"
  [ -f "$NGX_CONF" ] || die "verify nginx: finixo conf missing"
  ok "verify: Nginx active and config valid"
}

verify_firewall() {
  command -v ufw >/dev/null 2>&1 || { warn "verify firewall: ufw not installed"; return 0; }
  ufw status 2>/dev/null | gq -qi "Status: active" && ok "verify: UFW active" || warn "verify: UFW not active"
}

# spin "message" command args...   (runs quietly, shows a spinner, prints the
# tail of the log when the command fails)
spin() {
  local msg=$1 log pid rc i=0 f='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  shift
  init_work_dir || return 1
  log=$(mktemp "$WORK_DIR/spin.XXXXXX") || return 1
  "$@" >"$log" 2>&1 &
  pid=$!
  if [ -t 1 ]; then
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r%s  %s%s %s' "$C" "${f:i%10:1}" "$N" "$msg"
      i=$((i+1)); sleep 0.1
    done
  fi
  wait "$pid"; rc=$?
  if [ "$rc" -eq 0 ]; then
    printf '\r%s  ✓%s %s\033[K\n' "$G" "$N" "$msg"
  else
    printf '\r%s  ✗%s %s (exit %s)\033[K\n' "$R" "$N" "$msg" "$rc"
    tail -n 15 "$log" >&2 || true
  fi
  rm -f "$log"
  return "$rc"
}

pause() {
  [ -t 0 ] || return 0
  read -r -p "  Press Enter to continue..." _ || true
}

confirm() {
  if [ "${FINIXO_YES:-0}" = 1 ]; then return 0; fi
  [ -t 0 ] || return 1
  local a
  read -r -p "  $1 [y/N]: " a || return 1
  [[ $a =~ ^[Yy]$ ]]
}

init_work_dir() {
  # Must be on an exec-capable filesystem: /run is often noexec, and we smoke-test
  # the Xray binary from WORK_DIR during download.
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then return 0; fi
  install -d -m 755 "$LOCK_DIR" || return 1
  install -d -m 1777 /var/tmp 2>/dev/null || true
  WORK_DIR=$(mktemp -d /var/tmp/finixo-work.XXXXXX) || return 1
  chmod 700 "$WORK_DIR" 2>/dev/null || true
  return 0
}

need_root() {
  [ "$(id -u)" -eq 0 ] || die "Run as root (sudo -i)."
  init_work_dir || die "Cannot create the work directory under /var/tmp."
}

cleanup() {
  if [ -n "${E2E_PID:-}" ]; then
    kill "$E2E_PID" 2>/dev/null || true
    wait "$E2E_PID" 2>/dev/null || true
    E2E_PID=""
  fi
  # A REinstall that died early: put the previous credentials back.
  if [ "${FINIXO_STATE_BACKUP:-0}" -eq 1 ] && [ -d "$STATE_BACKUP_DIR" ]; then
    FINIXO_STATE_BACKUP=0
    [ -f "$STATE_BACKUP_DIR/paths.env" ] && cp -a "$STATE_BACKUP_DIR/paths.env" "$ENV_FILE" 2>/dev/null
    [ -f "$STATE_BACKUP_DIR/config.json" ] && cp -a "$STATE_BACKUP_DIR/config.json" "$XRAY_CFG" 2>/dev/null
    [ -f "$STATE_BACKUP_DIR/expiry.db" ] && cp -a "$STATE_BACKUP_DIR/expiry.db" "$EXPIRY_DB" 2>/dev/null
    [ -f "$STATE_BACKUP_DIR/disabled.db" ] && cp -a "$STATE_BACKUP_DIR/disabled.db" "$DISABLED_DB" 2>/dev/null
    if [ -x "$XRAY_BIN" ] && [ -f "$XRAY_CFG" ]; then
      load_conf
      setup_bridge >/dev/null 2>&1 || true
      systemctl restart xray >/dev/null 2>&1 || true
      warn "Reinstall did not complete; the previous FinixoGate configuration was restored."
    fi
  fi
  if [ "${FINIXO_INSTALL_ACTIVE:-0}" -eq 1 ]; then
    if [ -f "$NGINX_DEFAULT_BACKUP" ] && [ ! -e /etc/nginx/sites-enabled/default ] && [ ! -f "$NGX_CONF" ]; then
      install -d -m 755 /etc/nginx/sites-enabled 2>/dev/null || true
      cp -a "$NGINX_DEFAULT_BACKUP" /etc/nginx/sites-enabled/default 2>/dev/null || true
      nginx -t >/dev/null 2>&1 && (systemctl reload nginx >/dev/null 2>&1 || true)
    fi
  fi
  if [ -n "${WORK_DIR:-}" ]; then rm -rf "$WORK_DIR" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ----------------------------------------------------------------------------
# Validation / parsing (defined before load_conf, which uses them)
# ----------------------------------------------------------------------------
validate_ssh_maxstartups() {
  [[ "$SSH_MAXSTARTUPS" =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] || return 1
  local a b c
  IFS=: read -r a b c <<< "$SSH_MAXSTARTUPS"
  [ "$a" -ge 1 ] || return 1
  [ "$b" -ge 0 ] && [ "$b" -le 100 ] || return 1
  [ "$c" -ge "$a" ] && [ "$c" -le 65535 ] || return 1
}

validate_ssh_forwarding() {
  case "$SSH_TCP_FORWARDING" in local|yes) return 0 ;; *) return 1 ;; esac
}

validate_ngx_limits() {
  local v
  # 0 = disabled (no nginx limit_req/limit_conn on paths)
  for v in "$NGX_LIMIT_CONN" "$NGX_LIMIT_RATE" "$NGX_LIMIT_BURST"; do
    [[ "$v" =~ ^[0-9]+$ ]] || return 1
  done
  return 0
}

validate_dns_name() {
  local v=$1
  [ -n "$v" ] || return 1
  [ "${#v}" -le 253 ] || return 1
  [[ "$v" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$ ]]
}

validate_ipv4() {
  local v=$1 octet
  local -a octets
  [[ "$v" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<< "$v"
  [ "${#octets[@]}" -eq 4 ] || return 1
  for octet in "${octets[@]}"; do
    [ "$((10#$octet))" -le 255 ] || return 1
  done
}

# A host name or an IPv4 address. No reachability / ownership check: any value
# is accepted, because Remote Proxy, SNI and Host are free-form client fields.
validate_client_host() {
  # Free-form (SNI / Host / proxy host): any non-empty token, no spaces.
  local v=$1
  [ -n "$v" ] || return 1
  [ "${#v}" -le 253 ] || return 1
  [[ "$v" != *[[:space:]]* ]] || return 1
  return 0
}

parse_remote_proxy() {
  local raw=$1 host port
  REMOTE_PROXY_HOST=""; REMOTE_PROXY_PORT=""
  if [[ "$raw" =~ ^\[([^]]+)\]:([0-9]{1,5})$ ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
  elif [[ "$raw" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
  else
    host="$raw"; port=443
  fi
  [ -n "$host" ] || return 1
  [ "$((10#$port))" -ge 1 ] && [ "$((10#$port))" -le 65535 ] || return 1
  port=$((10#$port))
  if [[ "$host" == *:* ]]; then
    [[ "$raw" == \[*\]:* ]] || return 1
    python3 -c 'import ipaddress,sys; ipaddress.IPv6Address(sys.argv[1])' "$host" >/dev/null 2>&1 || return 1
  else
    validate_client_host "$host" || return 1
  fi
  REMOTE_PROXY_HOST=$host
  REMOTE_PROXY_PORT=$port
  if [[ "$host" == *:* ]]; then REMOTE_PROXY="[$host]:$port"; else REMOTE_PROXY="$host:$port"; fi
}

validate_client_profile_syntax() {
  parse_remote_proxy "$REMOTE_PROXY" || return 1
  validate_client_host "$CLIENT_SNI" || return 1
  validate_client_host "$CLIENT_HOST" || return 1
  case "$CLIENT_SEC" in auto|tls|none) ;; *) return 1 ;; esac
  case "$CLIENT_PIN" in auto|yes|no) ;; *) return 1 ;; esac
}

load_conf() {
  local key value
  SERVER_ADDR=""; REMOTE_PROXY=""; CLIENT_SNI=""; CLIENT_HOST=""
  CLIENT_SEC=auto; CLIENT_PIN=auto
  WSP_VLESS=""; WSP_VMESS=""; WSP_TROJAN=""; WSP_SS=""; WSP_SSH=""
  if [ -r "$ENV_FILE" ]; then
    while IFS='=' read -r key value; do
      [ -n "$key" ] || continue
      case "$key" in
        \#*) continue ;;
        WSP_VLESS|WSP_VMESS|WSP_TROJAN|WSP_SS|WSP_SSH|SERVER_ADDR|REMOTE_PROXY|CLIENT_SNI|CLIENT_HOST|CLIENT_SEC|CLIENT_PIN)
          value=${value#\"}; value=${value%\"}
          printf -v "$key" '%s' "$value"
          ;;
        FINIXO_EDGE)
          value=${value#\"}; value=${value%\"}
          if [ "${_FINIXO_EDGE_EXPLICIT:-0}" = 1 ] || [ "${FINIXO_SKIP_HAP:-0}" = 1 ]; then
            :
          else
          printf -v "$key" '%s' "$value"
          fi
          ;;
        FINIXO_DISABLE_IPV6)
          value=${value#\"}; value=${value%\"}
          if [ "${_FINIXO_IPV6_EXPLICIT:-0}" = 1 ]; then
            :
          else
          printf -v "$key" '%s' "$value"
          fi
          ;;
        SSH_MAXSTARTUPS|SSH_TCP_FORWARDING|NGX_LIMIT_CONN|NGX_LIMIT_RATE|NGX_LIMIT_BURST)
          value=${value#\"}; value=${value%\"}
          case "$ENV_OVERRIDE" in *" $key "*) ;; *) printf -v "$key" '%s' "$value" ;; esac
          ;;
      esac
    done < "$ENV_FILE"
  fi
  [ -n "$SERVER_ADDR" ] || SERVER_ADDR=$(cat "$CONF_DIR/domain" 2>/dev/null || true)   # legacy installs
  SERVER_IP=$(cat "$IP_FILE" 2>/dev/null || true)
  [ -n "$SERVER_ADDR" ] || SERVER_ADDR=$SERVER_IP
  DOMAIN=$SERVER_ADDR
  # 1.4.0: Client Profile removed — links always use this server's address
  lock_profile_to_server
}

# Always lock client endpoint to this server (Remote/SNI/Host editing removed).
lock_profile_to_server() {
  [ -n "${SERVER_ADDR:-}" ] || return 0
  # Default: links use this server. Optional CDN/remote via env (survives load_conf via ENV_OVERRIDE):
  #   FINIXO_REMOTE_PROXY=cdn.example.com:443 FINIXO_SNI=cdn.example.com FINIXO_HOST=cdn.example.com
  if [ -n "${FINIXO_REMOTE_PROXY:-}" ]; then
    REMOTE_PROXY="$FINIXO_REMOTE_PROXY"
    CLIENT_SNI="${FINIXO_SNI:-${REMOTE_PROXY%%:*}}"
    CLIENT_HOST="${FINIXO_HOST:-$CLIENT_SNI}"
  else
    REMOTE_PROXY="${SERVER_ADDR}:443"
    CLIENT_SNI="$SERVER_ADDR"
    CLIENT_HOST="$SERVER_ADDR"
  fi
  CLIENT_SEC=${CLIENT_SEC:-auto}
  CLIENT_PIN=${CLIENT_PIN:-auto}
  parse_remote_proxy "$REMOTE_PROXY" >/dev/null 2>&1 || true
}

write_client_profile() {
  lock_profile_to_server
  validate_client_profile_syntax || return 1
  local tmp _edge_save
  install -d -m 755 "$CONF_DIR" || return 1
  # Do not persist a temporary nginx fallback forced by FINIXO_SKIP_HAP=1
  _edge_save="${FINIXO_EDGE:-haproxy}"
  if [ "${FINIXO_SKIP_HAP:-0}" = 1 ]; then
    _edge_save=$(grep -E '^FINIXO_EDGE=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"' || true)
    _edge_save=${_edge_save:-haproxy}
  fi
  tmp=$(mktemp "$CONF_DIR/.paths.XXXXXX") || return 1
  cat > "$tmp" <<EOF2
WSP_VLESS="$WSP_VLESS"
WSP_VMESS="$WSP_VMESS"
WSP_TROJAN="$WSP_TROJAN"
WSP_SS="$WSP_SS"
WSP_SSH="$WSP_SSH"
FINIXO_EDGE="${_edge_save}"
FINIXO_DISABLE_IPV6="${FINIXO_DISABLE_IPV6:-1}"
SERVER_ADDR="$SERVER_ADDR"
REMOTE_PROXY="$REMOTE_PROXY"
CLIENT_SNI="$CLIENT_SNI"
CLIENT_HOST="$CLIENT_HOST"
CLIENT_SEC="$CLIENT_SEC"
CLIENT_PIN="$CLIENT_PIN"
SSH_MAXSTARTUPS="$SSH_MAXSTARTUPS"
SSH_TCP_FORWARDING="$SSH_TCP_FORWARDING"
NGX_LIMIT_CONN="$NGX_LIMIT_CONN"
NGX_LIMIT_RATE="$NGX_LIMIT_RATE"
NGX_LIMIT_BURST="$NGX_LIMIT_BURST"
EOF2
  chmod 600 "$tmp" || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$ENV_FILE" || { rm -f "$tmp"; return 1; }
}

# TLS on the client side: auto = off for the usual plain-HTTP ports.
client_tls() {
  case "$CLIENT_SEC" in tls) return 0 ;; none) return 1 ;; esac
  case "${REMOTE_PROXY_PORT:-443}" in
    80|8080|8880|2052|2082|2086|2095) return 1 ;;
    *) return 0 ;;
  esac
}

# Pin this server's self-signed certificate in the links? auto = yes only when
# the client connects straight to this server (no remote proxy in between).
use_pin() {
  client_tls || return 1
  case "$CLIENT_PIN" in yes) return 0 ;; no) return 1 ;; esac
  # auto: pin only when certificate is self-signed (issuer==subject).
  # CA certs (Let's Encrypt) rotate fingerprint on renew — pinning would break links.
  if [ -f "$TLS_CRT" ]; then
    local issuer subject
    issuer=$(openssl x509 -issuer -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^issuer=//')
    subject=$(openssl x509 -subject -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^subject=//')
    [ -n "$issuer" ] && [ "$issuer" = "$subject" ] || return 1
  else
    return 1
  fi
  [ "${REMOTE_PROXY_HOST,,}" = "${SERVER_ADDR,,}" ] || [ "${REMOTE_PROXY_HOST,,}" = "${SERVER_IP,,}" ]
}

tls_mode_text() {
  if ! client_tls; then echo "plain WebSocket (no TLS)"
  elif use_pin; then echo "TLS, self-signed cert pinned"
  else echo "TLS, verified by the remote proxy cert"
  fi
}

# ----------------------------------------------------------------------------
# System helpers
# ----------------------------------------------------------------------------
check_os() {
  [ -r /etc/os-release ] || die "Cannot detect the OS."
  local id ver
  id=$(. /etc/os-release; echo "${ID:-}")
  ver=$(. /etc/os-release; echo "${VERSION_ID:-}")
  case "$id:$ver" in
    ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
    *) [ "${FINIXO_FORCE:-0}" = 1 ] || die "Unsupported OS ($id $ver). Use Ubuntu 22.04/24.04/26.04 or Debian 12/13 (or FINIXO_FORCE=1)." ;;
  esac
  command -v systemctl >/dev/null 2>&1 || die "systemd is required."
}

is_installed() {
  [ -x "$XRAY_BIN" ] || return 1
  [ -f "$XRAY_CFG" ] || return 1
  [ -f "$ENV_FILE" ] || return 1
  [ -f /etc/systemd/system/xray.service ] || return 1
  [ -f /etc/systemd/system/finixo-ssh-ws.service ] || return 1
  [ -x "$BRIDGE" ] && [ -x "$HOLD" ] || return 1
  [ -f "$SSH_DROPIN" ] || return 1
  [ -f "$NGX_CONF" ] || return 1
  [ -f "$TLS_CRT" ] && [ -f "$TLS_KEY" ] || return 1
  if [ -f "$ENV_FILE" ] && grep -q '^FINIXO_EDGE=haproxy' "$ENV_FILE" 2>/dev/null; then
    [ -f "${HAP_CFG:-/etc/haproxy/haproxy.cfg}" ] || return 1
  fi
  return 0
}

# True if IPv4 is globally routable (not RFC1918 / loopback / link-local / CGNAT).
is_public_ipv4() {
  validate_ipv4 "$1" || return 1
  case "$1" in
    10.*|127.*|169.254.*|192.168.*) return 1 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 1 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 1 ;; # CGNAT
    0.*|255.*) return 1 ;;
  esac
  return 0
}

get_ipv4() {
  local u ip c
  if command -v curl >/dev/null 2>&1; then
    for u in https://ipv4.icanhazip.com https://api.ipify.org https://ifconfig.me/ip; do
      ip=$(curl -4 -fsS --max-time 4 "$u" 2>/dev/null | tr -d '[:space:]')
      if is_public_ipv4 "$ip"; then echo "$ip"; return 0; fi
    done
  fi
  # Offline / firewalled fallback: source address used to reach 1.1.1.1 (skip private)
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
  if is_public_ipv4 "$ip"; then echo "$ip"; return 0; fi
  # hostname -I may list private first on NAT VPSes — take first public only
  for c in $(hostname -I 2>/dev/null); do
    if is_public_ipv4 "$c"; then echo "$c"; return 0; fi
  done
  return 1
}

rand_hex() { openssl rand -hex "$1"; }
new_uuid() { cat /proc/sys/kernel/random/uuid; }

url_encode() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe="-._~"))
PY
}

b64_oneline() {
  if base64 -w0 </dev/null >/dev/null 2>&1; then printf '%s' "$1" | base64 -w0
  else printf '%s' "$1" | base64 | tr -d '\n'; fi
}
b64url_oneline() { b64_oneline "$1" | tr '+/' '-_' | tr -d '='; }

ssh_listen_ports() {
  {
    sshd -T 2>/dev/null | awk '/^port /{print $2}'
    systemctl show ssh.socket -p Listen 2>/dev/null | sed -nE 's/^Listen=.*:([0-9]+) \(Stream\)$/\1/p'
    systemctl show sshd.socket -p Listen 2>/dev/null | sed -nE 's/^Listen=.*:([0-9]+) \(Stream\)$/\1/p'
  } | awk '/^[0-9]+$/ && !seen[$0]++'
}

ssh_ports_all() {
  {
    ssh_listen_ports
    ss -ltnpH 2>/dev/null | awk '/users:\(\("sshd"/ {k=split($4,a,":"); print a[k]}'
  } | awk '/^[0-9]+$/ && !seen[$0]++'
}

ssh_port() {
  local p listening
  # Prefer a port that is actually listening (sshd or socket activation)
  listening=$(ss -ltnH 2>/dev/null | awk '{print $4}')
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    if grep -Eq "^(0\.0\.0\.0|\*|\[::\]|127\.0\.0\.1):${p}\$" <<< "$listening"; then echo "$p"; return 0; fi
  done < <(ssh_ports_all)
  p=$(ssh_ports_all | head -n1)
  echo "${p:-22}"
}

reload_ssh() {
  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || \
  systemctl reload ssh.socket >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || \
  systemctl restart sshd >/dev/null 2>&1
}

wait_active() {
  local s=$1 n=${2:-15} i
  for ((i=0; i<n; i++)); do
    systemctl is-active --quiet "$s" && return 0
    sleep 0.5
  done
  return 1
}

wait_port() {
  local port=$1 n=${2:-20} i
  for ((i=0; i<n; i++)); do
    if ss -ltnH 2>/dev/null | awk -v p="$port" '{k=split($4,a,":"); if (a[k]==p) f=1} END{exit(f?0:1)}'; then return 0; fi
    sleep 0.25
  done
  return 1
}

journal_hint() {
  command -v journalctl >/dev/null 2>&1 || return 0
  printf '%s--- %s (last 30) ---%s\n' "$Y" "$1" "$N"
  journalctl -u "$1" -n 30 --no-pager -l 2>/dev/null || true
}

# 0 = written (changed), 1 = identical (unchanged), 2 = error
write_atomic_from_stdin() {
  local dest=$1 mode=${2:-644} dir tmp
  dir=$(dirname "$dest")
  install -d -m 755 "$dir" || return 2
  tmp=$(mktemp "$dir/.finixo-write.XXXXXX") || return 2
  if ! cat > "$tmp"; then rm -f "$tmp"; return 2; fi
  if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    # Content unchanged — still enforce requested mode (e.g. 755 for bridge)
    [ "$(stat -c '%a' "$dest" 2>/dev/null)" = "$mode" ] || chmod "$mode" "$dest" 2>/dev/null || true
    return 1
  fi
  chmod "$mode" "$tmp" || { rm -f "$tmp"; return 2; }
  mv -f "$tmp" "$dest" || { rm -f "$tmp"; return 2; }
  return 0
}

cfg_lock() {
  install -d -m 755 "$LOCK_DIR" || return 1
  if [ "${FINIXO_LOCK_HELD:-0}" != 1 ]; then
    exec 9>"$LOCK_DIR/config.lock" || return 1
    if ! flock -w 30 9; then err "Could not lock $LOCK_DIR/config.lock"; exec 9>&- 2>/dev/null || true; return 1; fi
    FINIXO_LOCK_HELD=1
  fi
}
cfg_unlock() {
  if [ "${FINIXO_LOCK_HELD:-0}" = 1 ]; then
    flock -u 9 2>/dev/null || true
    exec 9>&- 2>/dev/null || true
    FINIXO_LOCK_HELD=0
  fi
}

install_packages() {
  spin "Updating package lists" env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 update -y \
    || die "apt update failed."
  spin "Installing nginx, haproxy, openssl, jq, ufw, chrony, certbot ..." env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    apt-get -o DPkg::Lock::Timeout=120 install -y \
    nginx haproxy curl unzip jq openssl socat ca-certificates ufw python3 chrony certbot nftables \
    iproute2 openssh-server logrotate coreutils util-linux procps \
    || die "apt install failed."
  command -v python3 >/dev/null 2>&1 || die "python3 missing after apt install."
  command -v jq >/dev/null 2>&1 || die "jq missing after apt install."
  command -v nginx >/dev/null 2>&1 || die "nginx missing after apt install."
  command -v haproxy >/dev/null 2>&1 || die "haproxy missing after apt install."
}

ensure_time_sync() {
  command -v timedatectl >/dev/null 2>&1 && timedatectl set-ntp true >/dev/null 2>&1 || true
  if systemctl cat chrony.service >/dev/null 2>&1; then
    systemctl enable --now chrony.service >/dev/null 2>&1 || true
  elif systemctl cat chronyd.service >/dev/null 2>&1; then
    systemctl enable --now chronyd.service >/dev/null 2>&1 || true
  fi
  local i synced="" tracking
  for ((i=0; i<20; i++)); do
    if command -v timedatectl >/dev/null 2>&1; then
      synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
      [ "$synced" = yes ] && return 0
    fi
    if command -v chronyc >/dev/null 2>&1; then
      tracking=$(chronyc tracking 2>/dev/null || true)
      grep -qiE 'Leap status[[:space:]]*:[[:space:]]*Normal' <<< "$tracking" && return 0
    fi
    sleep 1
  done
  return 1
}

is_container() { systemd-detect-virt -cq 2>/dev/null; }

# ----------------------------------------------------------------------------
# TLS (self-signed)
# ----------------------------------------------------------------------------
gen_tls_cert() {
  local cn=${1:-localhost} san
  install -d -m 700 "$TLS_DIR" || return 1
  if validate_ipv4 "$cn"; then san="IP:$cn"; else san="DNS:$cn"; fi
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$TLS_KEY" -out "$TLS_CRT" -days 3650 \
    -subj "/CN=$cn" -addext "subjectAltName=$san" >/dev/null 2>&1 || return 1
  chmod 600 "$TLS_KEY"; chmod 644 "$TLS_CRT"
}

# Free port 80 for ACME standalone challenge.
# Portable PIDs listening on a TCP port (works with mawk; no gawk match 3-arg).
_pids_on_port() {
  local port=$1 out
  # Extract every pid=N (ss may list several users on one line). Portable: no gawk.
  out=$(ss -tlnpH "sport = :${port}" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
  if [ -z "$out" ]; then
    out=$(ss -tlnp "sport = :${port}" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
  fi
  printf '%s\n' "$out"
}

# Soft free: only stop nginx briefly for standalone ACME. Never disable other daemons permanently.
free_port_80() {
  info "Temporarily releasing port 80 for ACME (nginx/haproxy)..."
  systemctl stop haproxy 2>/dev/null || true
  systemctl stop nginx 2>/dev/null || true
  sleep 1
  local pids
  pids=$(_pids_on_port 80 | tr '\n' ' ' | sed 's/[[:space:]]*$//')
  if [ -n "$pids" ]; then
    local p owner
    for p in $pids; do
      owner=$(ps -o comm= -p "$p" 2>/dev/null || true)
      case "$owner" in
        nginx|nginx:*|haproxy|haproxy:*) kill -TERM "$p" 2>/dev/null || true ;;
        *) warn "Port 80 held by $owner (pid $p) — not killing; prefer webroot challenge" ;;
      esac
    done
    sleep 1
  fi
  if ss -tlnp "sport = :80" 2>/dev/null | gq -q LISTEN; then
    warn "Port 80 still in use — will try webroot challenge instead of standalone"
    return 1
  fi
  ok "Port 80 is free"
  return 0
}

# Issue certificate: certbot webroot (preferred) → standalone → self-signed.
# Auto-renew via certbot.timer + deploy hook (copies into $TLS_* and reloads nginx).
# Writes into $TLS_CRT / $TLS_KEY so the rest of FinixoGate stays unchanged.
# 0 only when $TLS_CRT really covers $1 (a domain or an IP). openssl prints the verdict and its exit
# status is not a reliable signal, so the text is what counts.
cert_matches_domain() {
  local d=${1:-} out
  [ -f "$TLS_CRT" ] && [ -n "$d" ] || return 1
  if validate_ipv4 "$d"; then out=$(openssl x509 -noout -checkip "$d" -in "$TLS_CRT" 2>/dev/null) || true
  else out=$(openssl x509 -noout -checkhost "$d" -in "$TLS_CRT" 2>/dev/null) || true; fi
  [[ $out == *"does match certificate"* ]]
}

issue_cert() {
  local domain=$1
  local got=0 cb_log le issuer subject is_selfsigned=0 webroot_ok=0

  install -d -m 700 "$TLS_DIR" || return 1
  install -d -m 755 "$SITE_ROOT/.well-known/acme-challenge" || true

  # Skip if a real CA cert already exists and is valid > 7 days
  if [ -f "$TLS_CRT" ] && [ -f "$TLS_KEY" ]; then
    issuer=$(openssl x509 -issuer -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^issuer=//' || echo "")
    subject=$(openssl x509 -subject -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^subject=//' || echo "")
    [ "$issuer" = "$subject" ] && is_selfsigned=1
    if [ "${FINIXO_FORCE_CERT:-0}" != 1 ] && [ "$is_selfsigned" -eq 0 ] \
       && openssl x509 -checkend $((7*86400)) -noout -in "$TLS_CRT" 2>/dev/null \
       && cert_matches_domain "$domain"; then
      ok "CA-signed certificate already valid — ensuring auto-renew hooks"
      setup_cert_auto_renew "$domain" || true
      return 0
    fi
    if [ "$is_selfsigned" -eq 0 ] && ! cert_matches_domain "$domain"; then
      warn "The installed certificate does not cover $domain (it was issued for another name) — requesting a new one."
    fi
  fi

  # IP addresses cannot get a public certificate
  if validate_ipv4 "$domain"; then
    warn "Server address is an IP — public CA certificates require a domain. Using self-signed."
    gen_tls_cert "$domain" || return 1
    ok "Self-signed certificate created for IP $domain"
    return 0
  fi

  init_work_dir || true
  cb_log=$(mktemp "$WORK_DIR/certbot.XXXXXX") || cb_log="$WORK_DIR/certbot.log"

  if ! command -v certbot >/dev/null 2>&1; then
    info "Installing certbot..."
    env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y -qq certbot >/dev/null 2>&1 || true
  fi

  le="/etc/letsencrypt/live/${domain}"

  # --- Preferred: webroot (nginx can stay up; renew works forever) ---
  if command -v certbot >/dev/null 2>&1; then
    # Ensure nginx is up and serves ACME path
    if ! systemctl is-active --quiet nginx 2>/dev/null; then
      systemctl start nginx >/dev/null 2>&1 || true
    fi
    # Minimal server for webroot if conf not written yet
    if [ ! -f "$NGX_CONF" ]; then
      install -d -m 755 "$SITE_ROOT/.well-known/acme-challenge"
      cat > /etc/nginx/conf.d/99-finixo-acme.conf <<ACME
server {
    listen 80 default_server;
    server_name _;
    root $SITE_ROOT;
    location ^~ /.well-known/acme-challenge/ { default_type text/plain; allow all; }
    location / { return 204; }
}
ACME
      nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
    fi

    info "Trying certbot webroot (Let's Encrypt) — strongest stable path with Nginx..."
    # webroot: nginx stays up; renew does not fight port 80
    le_email_prepare
    local flags="--webroot -w $SITE_ROOT --agree-tos $LE_EMAIL_FLAG --non-interactive --preferred-challenges http"
    install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy 2>/dev/null || true
    setup_cert_auto_renew "$domain" >/dev/null 2>&1 || true
    # Only attach deploy-hook if the script is executable (avoids certbot abort)
    if [ -x /etc/letsencrypt/renewal-hooks/deploy/finixo-nginx.sh ]; then
      flags="$flags --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/finixo-nginx.sh"
    fi
    if [ "${FINIXO_FORCE_CERT:-0}" = 1 ]; then flags="$flags --force-renewal"; elif [ -f "${le}/fullchain.pem" ]; then flags="$flags --reinstall"; fi
    if certbot certonly $flags -d "$domain" >"$cb_log" 2>&1; then
      if [ -f "${le}/fullchain.pem" ] && [ -f "${le}/privkey.pem" ]; then
        install -m 644 "${le}/fullchain.pem" "$TLS_CRT"
        install -m 600 "${le}/privkey.pem"  "$TLS_KEY"
        got=1
        webroot_ok=1
        ok "Certificate issued via certbot webroot (auto-renew ready)"
      fi
    else
      warn "certbot webroot failed:"
      tail -n 6 "$cb_log" 2>/dev/null | sed 's/^/    /' || true
    fi
  fi

  # --- Fallback: standalone (brief nginx stop; only our nginx) ---
  if [ "$got" -eq 0 ] && command -v certbot >/dev/null 2>&1; then
    if free_port_80; then
      info "Trying certbot standalone..."
      le_email_prepare
      flags="--standalone --agree-tos $LE_EMAIL_FLAG --non-interactive --preferred-challenges http"
      if [ "${FINIXO_FORCE_CERT:-0}" = 1 ]; then flags="$flags --force-renewal"; elif [ -f "${le}/fullchain.pem" ]; then flags="$flags --reinstall"; fi
      if certbot certonly $flags -d "$domain" >"$cb_log" 2>&1; then
        if [ -f "${le}/fullchain.pem" ] && [ -f "${le}/privkey.pem" ]; then
          install -m 644 "${le}/fullchain.pem" "$TLS_CRT"
          install -m 600 "${le}/privkey.pem"  "$TLS_KEY"
          got=1
          ok "Certificate issued via certbot standalone"
        fi
      else
        warn "certbot standalone failed:"
        tail -n 6 "$cb_log" 2>/dev/null | sed 's/^/    /' || true
      fi
    fi
    systemctl start nginx >/dev/null 2>&1 || true
    if [ "${FINIXO_EDGE:-haproxy}" = haproxy ]; then
      systemctl start haproxy >/dev/null 2>&1 || true
    fi
  fi

  # --- Self-signed fallback (never wipe a still-valid public CA cert) ---
  if [ "$got" -eq 0 ]; then
    if [ -f "$TLS_CRT" ] && [ -f "$TLS_KEY" ]; then
      issuer=$(openssl x509 -issuer -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^issuer=//' || true)
      subject=$(openssl x509 -subject -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^subject=//' || true)
      end=$(openssl x509 -enddate -noout -in "$TLS_CRT" 2>/dev/null | sed 's/notAfter=//' || true)
      still_valid=0
      if [ -n "$end" ] && [ "$issuer" != "$subject" ]; then
        if openssl x509 -checkend 86400 -noout -in "$TLS_CRT" 2>/dev/null \
           && cert_matches_domain "$domain"; then
          still_valid=1
        fi
      fi
      if [ "$still_valid" = 1 ]; then
        warn "ACME failed — keeping the existing CA certificate for this domain (not replacing with self-signed)."
        warn "Fix DNS/port 80, then: finixo cert"
        got=1
      elif [ -f "$TLS_CRT" ] && [ "$issuer" != "$subject" ]; then
        warn "Existing CA cert does not match $domain (or is expiring) — will try self-signed only if ACME failed."
      fi
    fi
  fi
  if [ "$got" -eq 0 ]; then
    warn "Public certificate failed. Generating self-signed (clients will see a TLS warning)."
    warn "Open port 80, point the domain A record here, then: finixo cert"
    gen_tls_cert "$domain" || return 1
    ok "Self-signed certificate created"
  fi

  rm -f "$cb_log" 2>/dev/null || true
  rm -f /etc/nginx/conf.d/99-finixo-acme.conf 2>/dev/null || true
  setup_cert_auto_renew "$domain" || true
  return 0
}

# Install deploy hook + enable certbot.timer for automatic renewal without downtime.
setup_cert_auto_renew() {
  local domain=${1:-}
  install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy 2>/dev/null || return 0
  cat > /etc/letsencrypt/renewal-hooks/deploy/finixo-nginx.sh <<'HOOK'
#!/bin/sh
# FinixoGate: renew hook — only apply certs for THIS host domain
set -e
RENEWED_DOMAINS=${RENEWED_DOMAINS:-}
WANT=""
[ -f /etc/finixo/domain ] && WANT=$(head -1 /etc/finixo/domain 2>/dev/null | tr -d "[:space:]")
[ -z "$WANT" ] && [ -f /etc/finixo/paths.env ] && WANT=$(grep -E "^SERVER_ADDR=" /etc/finixo/paths.env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\"")
applied=0
for dom in $RENEWED_DOMAINS; do
  # Skip foreign domains on multi-cert hosts
  if [ -n "$WANT" ] && [ "$dom" != "$WANT" ]; then
    continue
  fi
  crt="/etc/letsencrypt/live/${dom}/fullchain.pem"
  key="/etc/letsencrypt/live/${dom}/privkey.pem"
  if [ -f "$crt" ] && [ -f "$key" ]; then
    install -d -m 700 /etc/finixo/tls
    install -m 644 "$crt" /etc/finixo/tls/server.crt
    install -m 600 "$key" /etc/finixo/tls/server.key
    applied=1
  fi
done
# If certbot did not pass RENEWED_DOMAINS, fall back to lineage only when it matches WANT
if [ "$applied" = 0 ] && [ -n "${RENEWED_LINEAGE:-}" ] && [ -f "$RENEWED_LINEAGE/fullchain.pem" ]; then
  base=$(basename "$RENEWED_LINEAGE")
  if [ -z "$WANT" ] || [ "$base" = "$WANT" ]; then
    install -d -m 700 /etc/finixo/tls
    install -m 644 "$RENEWED_LINEAGE/fullchain.pem" /etc/finixo/tls/server.crt
    install -m 600 "$RENEWED_LINEAGE/privkey.pem" /etc/finixo/tls/server.key
    applied=1
  fi
fi
[ "$applied" = 1 ] || exit 0
if [ -f /etc/finixo/tls/server.crt ] && [ -f /etc/finixo/tls/server.key ]; then
  { cat /etc/finixo/tls/server.crt; echo; cat /etc/finixo/tls/server.key; echo; } > /etc/finixo/tls/haproxy.pem
  chmod 600 /etc/finixo/tls/haproxy.pem
fi
if command -v nginx >/dev/null 2>&1; then
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx >/dev/null 2>&1 || true
  fi
fi
EDGE=haproxy
[ -f /etc/finixo/paths.env ] && EDGE=$(grep -E "^FINIXO_EDGE=" /etc/finixo/paths.env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d "\"")
EDGE=${EDGE:-haproxy}
if [ "$EDGE" = haproxy ] && command -v haproxy >/dev/null 2>&1 && [ -f /etc/haproxy/haproxy.cfg ]; then
  if systemctl is-enabled haproxy >/dev/null 2>&1 || systemctl is-active haproxy >/dev/null 2>&1; then
    HAPB=$(command -v haproxy || echo /usr/sbin/haproxy)
    if "$HAPB" -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
      systemctl reload haproxy >/dev/null 2>&1 || systemctl restart haproxy >/dev/null 2>&1 || true
    fi
  fi
fi
HOOK
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/finixo-nginx.sh 2>/dev/null || true

  # Force webroot in renewal config if domain known
  if [ -n "$domain" ] && [ -f "/etc/letsencrypt/renewal/${domain}.conf" ]; then
    if ! grep -q "^\s*authenticator\s*=\s*webroot" "/etc/letsencrypt/renewal/${domain}.conf" 2>/dev/null; then
      sed -i 's/^\s*authenticator\s*=.*/authenticator = webroot/' "/etc/letsencrypt/renewal/${domain}.conf" 2>/dev/null || true
    fi
    if ! grep -q "^\s*webroot_path" "/etc/letsencrypt/renewal/${domain}.conf" 2>/dev/null; then
      printf '\nwebroot_path = %s\n[[webroot_map]]\n%s = %s\n' \
        "$SITE_ROOT" "$domain" "$SITE_ROOT" >> "/etc/letsencrypt/renewal/${domain}.conf" 2>/dev/null || true
    fi
  fi

  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
  # Also drop a weekly safety cron if timer missing
  if ! systemctl is-enabled certbot.timer >/dev/null 2>&1; then
    cat > /etc/cron.weekly/finixo-cert-renew <<'CRON'
#!/bin/sh
certbot renew --quiet --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/finixo-nginx.sh 2>/dev/null || true
CRON
    chmod 755 /etc/cron.weekly/finixo-cert-renew 2>/dev/null || true
  fi
  ok "Certificate auto-renew configured (certbot.timer + deploy hook)"
}

cert_is_selfsigned() {
  local i s
  [ -f "$TLS_CRT" ] || return 1
  i=$(openssl x509 -issuer -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^issuer=//')
  s=$(openssl x509 -subject -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^subject=//')
  [ -n "$i" ] && [ "$i" = "$s" ]
}

# lowercase hex SHA-256 of the DER certificate (Xray: pinnedPeerCertSha256)
cert_sha256() {
  openssl x509 -in "$TLS_CRT" -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
}

cert_menu() {
  local c fp a b pc pk
  while true; do
    clear 2>/dev/null || true
    load_conf
    u_title "TLS CERTIFICATE"
    echo "  Chain: certbot webroot → standalone → self-signed"
    echo "  Current server address: ${SERVER_ADDR:-not set}"
    printf "  Status: %s  kind=%s  days=%s\n" "$(cert_badge_plain)" "$(cert_kind_short)" "$(cert_days_left)"
    echo
    echo "  [1] Show fingerprint / expiry"
    echo "  [2] Re-issue certificate (force renew / replace)"
    echo "  [3] Force self-signed certificate"
    echo "  [4] Use my own certificate files"
    echo "  [5] Test auto-renew (certbot renew --dry-run)"
    echo "  [0] Back"
    read -r -p "  > " c || return 0
    case $c in
      1) if [ -f "$TLS_CRT" ]; then
           openssl x509 -in "$TLS_CRT" -noout -subject -issuer -enddate
           fp=$(cert_sha256)
           echo "  SHA-256 (hex)  : $fp"
           echo "  SHA-256 (colon): $(sed 's/../&:/g; s/:$//' <<< "$fp" | tr 'a-f' 'A-F')"
           printf "  Badge         : %s\n" "$(cert_badge_plain)"
         else err "No certificate."; fi
         pause ;;
      2) load_conf
         a=${SERVER_ADDR:-}
         [ -n "$a" ] || { err "Server address unknown."; pause; continue; }
         FINIXO_FORCE_CERT=1
         if issue_cert "$a"; then
           if write_nginx_full; then ok "Certificate updated."
           else err "Certificate issued, but Nginx rejected the new config."; fi
         else
           err "Could not issue the certificate."
           systemctl is-active --quiet nginx 2>/dev/null || systemctl restart nginx >/dev/null 2>&1 || true
         fi
         pause ;;
      5) if command -v certbot >/dev/null 2>&1; then
           info "Running certbot renew --dry-run (no changes)..."
           if certbot renew --dry-run 2>&1 | tail -n 20; then
             ok "Dry-run finished (check output above)."
           else
             warn "Dry-run reported problems — see messages above."
           fi
         else
           err "certbot not installed."
         fi
         pause ;;
      3) load_conf
         a=${SERVER_ADDR:-localhost}
         if gen_tls_cert "$a" && write_nginx_full; then
           ok "Self-signed certificate installed."
         else err "Could not generate the certificate."; fi
         pause ;;
      4) read -r -p "  Path of the certificate (PEM, full chain): " a
         read -r -p "  Path of the private key (PEM): " b
         if [ ! -r "$a" ] || [ ! -r "$b" ]; then err "File not readable."; pause; continue; fi
         if ! openssl x509 -in "$a" -noout >/dev/null 2>&1; then
           err "Not a valid PEM certificate: $a"; pause; continue
         fi
         if ! openssl pkey -in "$b" -noout >/dev/null 2>&1; then
           err "Not a valid PEM private key: $b"; pause; continue
         fi
         pc=$(openssl x509 -in "$a" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')
         pk=$(openssl pkey -in "$b" -pubout 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')
         if [ -z "$pc" ] || [ -z "$pk" ] || [ "$pc" != "$pk" ]; then
           err "Certificate and private key do not form a matching pair."; pause; continue
         fi
         install -d -m 700 "$TLS_DIR" || { err "Cannot create $TLS_DIR"; pause; continue; }
         cp -a "$TLS_CRT" "$TLS_CRT.bak" 2>/dev/null || true
         cp -a "$TLS_KEY" "$TLS_KEY.bak" 2>/dev/null || true
         if ! install -m 644 "$a" "$TLS_CRT" || ! install -m 600 "$b" "$TLS_KEY"; then
           err "Failed to install certificate files."; pause; continue
         fi
         if write_nginx_full; then
           ok "Certificate installed."
           info "If the certificate is from a public CA, pin (pcs=) is disabled automatically in links."
         else
           err "Nginx rejected it; restoring the previous certificate."
           [ -f "$TLS_CRT.bak" ] && cp -a "$TLS_CRT.bak" "$TLS_CRT"
           [ -f "$TLS_KEY.bak" ] && cp -a "$TLS_KEY.bak" "$TLS_KEY"
           write_nginx_full >/dev/null 2>&1 || true
         fi
         pause ;;
      0) return 0 ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# Shadowsocks 2022 / WebSocket paths
# ----------------------------------------------------------------------------
ss_method_valid() {
  case "$1" in 2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305|2022-blake3-aes-128-gcm) return 0 ;; *) return 1 ;; esac
}
ss_key_len() {
  case "$1" in
    2022-blake3-aes-128-gcm) echo 16 ;;
    2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305) echo 32 ;;
    *) return 1 ;;
  esac
}
ss_new_key() { local n; n=$(ss_key_len "$1") || return 1; openssl rand -base64 "$n"; }
ss_gen_password() { if ss_method_valid "$1"; then ss_new_key "$1"; else rand_hex 16; fi; }
ss_userinfo() {
  local m=$1 p=$2
  if [[ "$m" == 2022-* ]]; then printf '%s:%s' "$(url_encode "$m")" "$(url_encode "$p")"
  else b64url_oneline "$m:$p"; fi
}
ss_password() { jq -r --arg t ss-ws '.inbounds[]|select(.tag==$t).settings.password // empty' "$XRAY_CFG" 2>/dev/null; }
ss_method()   { jq -r --arg t ss-ws '.inbounds[]|select(.tag==$t).settings.method // empty' "$XRAY_CFG" 2>/dev/null; }
ss_key_ok() {
  local m p n len
  m=$(ss_method); p=$(ss_password)
  [ -n "$m" ] && [ -n "$p" ] || return 1
  ss_method_valid "$m" || return 1
  n=$(ss_key_len "$m") || return 1
  len=$(printf '%s' "$p" | base64 -d 2>/dev/null | wc -c)
  [ "$len" -eq "$n" ]
}
ss_upgrade_legacy() {
  local m s
  m=$(ss_method); [ -n "$m" ] || return 0
  ss_method_valid "$m" && return 0
  warn "Shadowsocks uses the legacy cipher '$m'; upgrading to $SS_METHOD (old links stop working)."
  s=$(ss_new_key "$SS_METHOD") || return 1
  cfg_apply --arg m "$SS_METHOD" --arg p "$s" '(.inbounds[]|select(.tag=="ss-ws").settings) |= (.method=$m | .password=$p)'
}

validate_ws_path() {
  local p=$1
  [[ "$p" =~ ^/[A-Za-z0-9._~/-]{1,120}$ ]] || return 1
  [[ "$p" != *//* ]] || return 1
  [[ "$p" != */ ]] || return 1
  [[ "$p" != /.well-known* ]] || return 1
  [[ "$p" != *..* ]] || return 1          # no "/../x" style traversal
  return 0
}
# Optional Let's Encrypt contact e-mail (expiry notices). FINIXO_LE_EMAIL, or asked once on a TTY.
# Sets LE_EMAIL_FLAG (call WITHOUT a subshell so the answer is remembered).
LE_EMAIL_FLAG=""
le_email_prepare() {
  [ -z "$LE_EMAIL_FLAG" ] || return 0
  local e=${FINIXO_LE_EMAIL:-}
  if [ -z "$e" ] && [ -t 0 ] && [ "${FINIXO_YES:-0}" != 1 ]; then
    read -r -t 20 -p "  E-mail for Let's Encrypt expiry notices (optional, Enter to skip): " e || e=""
  fi
  if [[ $e =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
    LE_EMAIL_FLAG="--email $e"
  else
    LE_EMAIL_FLAG="--register-unsafely-without-email"
  fi
}
gen_ws_path() {
  # Kept for optional custom use; default install uses fixed short paths.
  local h
  h=$(rand_hex 16)
  echo "/g/${h}"
}

choose_ws_paths() {
  # ONE path per protocol. Stable after first save in paths.env.
  # Fresh install (empty WSP_*): random CDN-like suffix so scanners cannot probe a global default.
  # Order: FINIXO_PATH_* env > paths.env (load_conf) > generate once.
  if [ -z "${WSP_VLESS:-}" ] && [ -z "${FINIXO_PATH_VLESS:-}" ]; then
    local sfx
    sfx=$(rand_hex 8 2>/dev/null || openssl rand -hex 4 2>/dev/null || echo "a1b2c3d4")
    WSP_VLESS="/cdn/assets/js/v${sfx}.chunk.js"
    WSP_VMESS="/cdn/assets/js/m${sfx}.chunk.js"
    WSP_TROJAN="/cdn/assets/js/t${sfx}.chunk.js"
    WSP_SS="/cdn/assets/js/s${sfx}.chunk.js"
    WSP_SSH="/cdn/assets/js/h${sfx}.chunk.js"
  fi
  WSP_VLESS=${FINIXO_PATH_VLESS:-${WSP_VLESS:-/cdn/assets/js/vless.chunk.js}}
  WSP_VMESS=${FINIXO_PATH_VMESS:-${WSP_VMESS:-/cdn/assets/js/vmess.chunk.js}}
  WSP_TROJAN=${FINIXO_PATH_TROJAN:-${WSP_TROJAN:-/cdn/assets/js/trojan.chunk.js}}
  WSP_SS=${FINIXO_PATH_SS:-${WSP_SS:-/cdn/assets/js/ss.chunk.js}}
  WSP_SSH=${FINIXO_PATH_SSH:-${WSP_SSH:-/cdn/assets/js/ssh.chunk.js}}

  local p
  for p in "$WSP_VLESS" "$WSP_VMESS" "$WSP_TROJAN" "$WSP_SS" "$WSP_SSH"; do
    validate_ws_path "$p" || { err "Invalid WebSocket path '$p'."; return 1; }
  done
  local -a all=("$WSP_VLESS" "$WSP_VMESS" "$WSP_TROJAN" "$WSP_SS" "$WSP_SSH")
  local i j
  for ((i=0; i<5; i++)); do
    for ((j=i+1; j<5; j++)); do
      [ "${all[$i]}" != "${all[$j]}" ] || { err "Path '${all[$i]}' is used twice."; return 1; }
    done
  done
  info "WebSocket paths: vless=$WSP_VLESS  vmess=$WSP_VMESS  trojan=$WSP_TROJAN  ss=$WSP_SS  ssh=$WSP_SSH"
}


# ----------------------------------------------------------------------------
# Xray
# ----------------------------------------------------------------------------
# First line of `xray version` WITHOUT a pipe (a pipe into head + pipefail
# makes xray die with SIGPIPE -> exit 141 -> false "install failed").
# `cmd | grep -q x` under pipefail can report FAILURE even when x matched (grep exits early, cmd gets
# SIGPIPE -> 141). gq drops the q so grep drains the pipe; use it in every pipeline.
gq() { local a args=(); for a in "$@"; do if [[ $a =~ ^-[A-Za-z]+$ ]]; then a=${a//q/}; [ "$a" = "-" ] && continue; fi; args+=("$a"); done; grep "${args[@]}" >/dev/null 2>&1; }

xray_ver_line() {
  local o
  o=$("${1:-$XRAY_BIN}" version 2>/dev/null) || true
  printf '%s\n' "${o%%$'\n'*}"
}

xray_arch_zip() {
  case "$(uname -m)" in
    x86_64|amd64) echo "Xray-linux-64.zip" ;;
    aarch64|arm64) echo "Xray-linux-arm64-v8a.zip" ;;
    *) return 1 ;;
  esac
}

# Official Xray zip + .dgst only. SHA256 mandatory; SHA512 when present.
# No install without digest match. Architecture from uname -m.
xray_download_staging() {
  local zip ver base tmp want256 want512 have256 have512 ver_tag found
  zip=$(xray_arch_zip) || { err "Unsupported CPU architecture: $(uname -m)"; return 1; }
  ver=${XRAY_VERSION:-latest}
  case "$ver" in latest|v*) ;; *) ver="v$ver" ;; esac
  init_work_dir || return 1
  tmp=$(mktemp -d "$WORK_DIR/xray.XXXXXX") || return 1

  resolve_base() {
    if [ "$1" = latest ]; then echo "https://github.com/XTLS/Xray-core/releases/latest/download"
    else echo "https://github.com/XTLS/Xray-core/releases/download/${1}"; fi
  }

  fetch_pair() {
    local b=$1
    rm -f "$tmp/$zip" "$tmp/$zip.dgst"
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --max-time 180 -o "$tmp/$zip" "$b/$zip" || return 1
    curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --max-time 30 -o "$tmp/$zip.dgst" "$b/$zip.dgst" || return 1
    return 0
  }

  info "Downloading Xray-core (${ver}) for $(uname -m) → $zip ..." >&2
  base=$(resolve_base "$ver")
  if ! fetch_pair "$base"; then
    warn "Primary fetch failed — resolving latest tag via API..." >&2
    ver_tag=$(curl -fsSL --max-time 15 "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null \
      | grep '"tag_name"' | head -1 | cut -d '"' -f4) || true
    [ -n "$ver_tag" ] || { rm -rf "$tmp"; err "Xray download failed (no tag)."; return 1; }
    base=$(resolve_base "$ver_tag")
    info "Retry with tag $ver_tag ..." >&2
    if ! fetch_pair "$base"; then
      rm -rf "$tmp"; err "Xray download failed (zip or .dgst missing)."; return 1
    fi
  fi

  # Only the labelled fields are used. A 64-hex slice of the SHA-512 line is NOT a SHA-256 digest.
  want256=$(awk -F'=' '{k=$1; gsub(/[[:space:]]/,"",k); k=toupper(k)} k=="SHA2-256"||k=="SHA-256"||k=="SHA256" {v=$2; gsub(/[[:space:]]/,"",v); print tolower(v); exit}' "$tmp/$zip.dgst")
  want512=$(awk -F'=' '{k=$1; gsub(/[[:space:]]/,"",k); k=toupper(k)} k=="SHA2-512"||k=="SHA-512"||k=="SHA512" {v=$2; gsub(/[[:space:]]/,"",v); print tolower(v); exit}' "$tmp/$zip.dgst")
  [[ $want256 =~ ^[0-9a-f]{64}$ ]] || { rm -rf "$tmp"; err "The .dgst file has no valid SHA2-256 entry — refusing to install (a SHA-512 value is never used as a SHA-256 substitute)."; return 1; }
  if [ -n "$want512" ] && ! [[ $want512 =~ ^[0-9a-f]{128}$ ]]; then want512=""; warn "Ignoring a malformed SHA2-512 entry in the .dgst file (SHA-256 is still enforced)." >&2; fi

  have256=$(sha256sum "$tmp/$zip" | awk '{print tolower($1)}')
  if [ "$have256" != "$want256" ]; then
    rm -rf "$tmp"; err "Xray SHA256 mismatch — refuse install."; return 1
  fi
  ok "Xray SHA256 verified" >&2

  if [ -n "$want512" ] && command -v sha512sum >/dev/null 2>&1; then
    have512=$(sha512sum "$tmp/$zip" | awk '{print tolower($1)}')
    if [ "$have512" != "$want512" ]; then
      rm -rf "$tmp"; err "Xray SHA512 mismatch — refuse install."; return 1
    fi
    ok "Xray SHA512 verified" >&2
  fi

  mkdir -p "$tmp/x" || { rm -rf "$tmp"; return 1; }
  unzip -tq "$tmp/$zip" >/dev/null 2>&1 || { rm -rf "$tmp"; err "Xray ZIP integrity test failed."; return 1; }
  unzip -oq "$tmp/$zip" -d "$tmp/x" || { rm -rf "$tmp"; err "Xray extraction failed."; return 1; }
  if [ ! -f "$tmp/x/xray" ]; then
    found=$(find "$tmp/x" -type f -name xray 2>/dev/null | head -n1)
    [ -n "$found" ] && mv -f "$found" "$tmp/x/xray"
  fi
  [ -f "$tmp/x/xray" ] || { rm -rf "$tmp"; err "Xray binary missing from the archive."; return 1; }
  chmod 755 "$tmp/x/xray" || { rm -rf "$tmp"; return 1; }
  if ! "$tmp/x/xray" version >/dev/null 2>&1; then
    rm -rf "$tmp"; err "Xray binary does not run (wrong arch/corrupt)."; return 1
  fi
  ok "Xray binary smoke test OK: $(xray_ver_line "$tmp/x/xray")" >&2
  [ -f "$tmp/x/geoip.dat" ] || find "$tmp/x" -name geoip.dat -exec cp {} "$tmp/x/geoip.dat" \; 2>/dev/null || true
  [ -f "$tmp/x/geosite.dat" ] || find "$tmp/x" -name geosite.dat -exec cp {} "$tmp/x/geosite.dat" \; 2>/dev/null || true
  echo "$tmp"
}

install_xray() {
  local tmp=$1 out dat geo_base="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
  if [ ! -f "$tmp/x/xray" ]; then err "Staged Xray binary not found: $tmp/x/xray"; return 1; fi
  install -d -m 755 "$XRAY_ASSET" || { err "Cannot create $XRAY_ASSET"; return 1; }
  install -d -m 755 "$(dirname "$XRAY_BIN")" || { err "Cannot create $(dirname "$XRAY_BIN")"; return 1; }
  rm -f "${XRAY_BIN}.new"
  install -m 755 "$tmp/x/xray" "${XRAY_BIN}.new" || { err "Cannot write ${XRAY_BIN}.new (disk full / read-only?)"; return 1; }
  # Prove the copy runs from its final filesystem (noexec mounts) BEFORE replacing the old binary.
  if ! out=$("${XRAY_BIN}.new" version 2>&1); then
    err "Xray cannot run from $(dirname "$XRAY_BIN"): ${out%%$'\n'*}"
    rm -f "${XRAY_BIN}.new"; return 1
  fi
  # A running xray keeps its inode, so an atomic rename is safe even on reinstall.
  mv -f "${XRAY_BIN}.new" "$XRAY_BIN" || { err "Cannot replace $XRAY_BIN"; rm -f "${XRAY_BIN}.new"; return 1; }
  [ -f "$tmp/x/geoip.dat" ]   && { install -m 644 "$tmp/x/geoip.dat"   "$XRAY_ASSET/geoip.dat"   || true; }
  [ -f "$tmp/x/geosite.dat" ] && { install -m 644 "$tmp/x/geosite.dat" "$XRAY_ASSET/geosite.dat" || true; }
  for dat in geoip.dat geosite.dat; do
    if [ ! -s "$XRAY_ASSET/$dat" ]; then
      info "Downloading missing $dat ..." >&2
      curl -fsSL --retry 2 --max-time 60 -o "$XRAY_ASSET/$dat" "${geo_base}/${dat}" 2>/dev/null || \
        warn "Could not download $dat — routing rules that use it may fail" >&2
    fi
  done
  if ! out=$("$XRAY_BIN" version 2>&1); then
    err "Installed Xray does not run: ${out%%$'\n'*}"; return 1
  fi
  printf '%s\n' "${out%%$'\n'*}"
  return 0
}

xray_remote_tag() {
  curl -fsSL --max-time 12 "https://api.github.com/repos/XTLS/Xray-core/releases/latest" 2>/dev/null \
    | grep '"tag_name"' | head -1 | cut -d '"' -f4
}

xray_local_ver() {
  [ -x "$XRAY_BIN" ] || { echo ""; return; }
  xray_ver_line | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

xray_update_state() {
  local loc rem cache=/run/finixo/xray-update.cache now mtime=0 age
  loc=$(xray_local_ver)
  [ -n "$loc" ] || { echo INSTALL; return; }
  now=$(date +%s)
  mkdir -p /run/finixo 2>/dev/null || true
  if [ -f "$cache" ]; then
    mtime=$(stat -c %Y "$cache" 2>/dev/null || echo 0)
    age=$((now - mtime))
    if [ "$age" -lt 3600 ]; then
      rem=$(awk -F= '/^remote=/{print $2; exit}' "$cache" 2>/dev/null)
    fi
  fi
  if [ -z "${rem:-}" ]; then
    rem=$(xray_remote_tag 2>/dev/null | sed 's/^v//')
    if [ -n "$rem" ]; then
      printf 'remote=%s\nlocal=%s\n' "$rem" "$loc" > "$cache" 2>/dev/null || true
    fi
  fi
  [ -n "$rem" ] || { echo UNKNOWN; return; }
  if [ "$loc" = "$rem" ]; then echo CURRENT
  else echo UPDATE
  fi
}


# Real memory ceiling in MiB: MemTotal, or the container's cgroup limit when that is smaller.
sys_mem_total_mib() {
  local t lim
  t=$(awk '/^MemTotal:/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
  t=${t:-0}
  for lim in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do
    if [ -r "$lim" ]; then
      lim=$(cat "$lim" 2>/dev/null)
      if [[ $lim =~ ^[0-9]+$ ]] && [ "$lim" -gt 0 ] && [ $((lim / 1048576)) -lt "$t" ]; then t=$((lim / 1048576)); fi
      break
    fi
  done
  echo "$t"
}

# Go soft memory limit for Xray (65% of RAM, min 192 MiB): keeps the heap bounded on small VPS
# so a long-running Xray never drifts into swap / OOM and slows every tunnel down.
xray_gomemlimit_mib() {
  local t l
  t=$(sys_mem_total_mib)
  [[ $t =~ ^[0-9]+$ ]] && [ "$t" -gt 0 ] || { echo 0; return; }
  l=$((t * 65 / 100)); [ "$l" -ge 192 ] || l=192
  echo "$l"
}

setup_xray_env() {
  local rc gml gml_line=""
  gml=$(xray_gomemlimit_mib)
  [ "${gml:-0}" -gt 0 ] && gml_line="Environment=GOMEMLIMIT=${gml}MiB"
  id xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xray || return 1
  install -d -m 750 -o root -g xray "$XRAY_DIR" || return 1
  install -d -m 750 -o xray -g xray "$XRAY_LOG" || return 1
  write_atomic_from_stdin /etc/logrotate.d/finixo-xray 644 <<EOF2
$XRAY_LOG/*.log {
    daily
    maxsize 100M
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
EOF2
  rc=$?; [ "$rc" -le 1 ] || return 1
  write_atomic_from_stdin /etc/systemd/system/xray.service 644 <<EOF2
[Unit]
Description=Xray-core (FinixoGate)
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
User=xray
Group=xray
Type=simple
Environment=XRAY_LOCATION_ASSET=$XRAY_ASSET
$gml_line
ExecStart=$XRAY_BIN run -format json -config $XRAY_CFG
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=2
TimeoutStopSec=10
LimitNOFILE=1048576
OOMScoreAdjust=-200
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectProc=invisible
LockPersonality=true
RestrictSUIDSGID=true
RestrictNamespaces=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
ReadWritePaths=$XRAY_LOG
ReadOnlyPaths=$XRAY_DIR $XRAY_ASSET

[Install]
WantedBy=multi-user.target
EOF2
  rc=$?; [ "$rc" -le 1 ] || return 1
  systemctl daemon-reload || return 1
}

fix_log_perms() {
  chown -R xray:xray "$XRAY_LOG" 2>/dev/null || true
  chmod 750 "$XRAY_LOG" 2>/dev/null || true
}

validate_xray_config_file() {
  local file=$1
  jq . "$file" >/dev/null 2>&1 || return 1
  "$XRAY_BIN" run -test -format json -config "$file" >/dev/null 2>&1
}

write_xray_config_initial() {
  local s tmp
  # No default users — add from menu (VLESS/VMess/Trojan start empty)
  ss_method_valid "$SS_METHOD" || { err "Invalid SS_METHOD='$SS_METHOD'"; return 1; }
  s=$(ss_new_key "$SS_METHOD") || return 1
  tmp=$(mktemp --suffix=.json "$XRAY_DIR/.config.XXXXXX") || return 1
  cat > "$tmp" <<EOF2
{
  "log": { "loglevel": "warning", "access": "none", "error": "$XRAY_LOG/error.log" },
  "inbounds": [
    {
      "tag": "api", "listen": "127.0.0.1", "port": $XRAY_API_PORT, "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    },
    {
      "tag": "vless-ws", "listen": "127.0.0.1", "port": $P_VLESS, "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "$WSP_VLESS", "heartbeatPeriod": 30 }, "sockopt": { "tcpKeepAliveInterval": 30, "tcpKeepAliveIdle": 60, "trustedXForwardedFor": [ "X-Forwarded-For" ] } }
    },
    {
      "tag": "vmess-ws", "listen": "127.0.0.1", "port": $P_VMESS, "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "$WSP_VMESS", "heartbeatPeriod": 30 }, "sockopt": { "tcpKeepAliveInterval": 30, "tcpKeepAliveIdle": 60, "trustedXForwardedFor": [ "X-Forwarded-For" ] } }
    },
    {
      "tag": "trojan-ws", "listen": "127.0.0.1", "port": $P_TROJAN, "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "$WSP_TROJAN", "heartbeatPeriod": 30 }, "sockopt": { "tcpKeepAliveInterval": 30, "tcpKeepAliveIdle": 60, "trustedXForwardedFor": [ "X-Forwarded-For" ] } }
    },
    {
      "tag": "ss-ws", "listen": "127.0.0.1", "port": $P_SS, "protocol": "shadowsocks",
      "settings": { "method": "$SS_METHOD", "password": "$s", "network": "tcp", "email": "default" },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "$WSP_SS", "heartbeatPeriod": 30 }, "sockopt": { "tcpKeepAliveInterval": 30, "tcpKeepAliveIdle": 60, "trustedXForwardedFor": [ "X-Forwarded-For" ] } }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": {} },
    { "tag": "block", "protocol": "blackhole", "settings": {} }
  ],
  "stats": {},
  "api": {
    "tag": "api",
    "services": [ "HandlerService", "StatsService" ]
  },
  "policy": {
    "levels": {
      "0": {
        "handshake": 8,
        "connIdle": 1800,
        "statsUserUplink": true,
        "statsUserDownlink": true,
        "statsUserOnline": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": [ "api" ], "outboundTag": "api" },
      { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" }
    ]
  }
}
EOF2
  chmod 640 "$tmp" || { rm -f "$tmp"; return 1; }
  chown root:xray "$tmp" || { rm -f "$tmp"; return 1; }
  if ! validate_xray_config_file "$tmp"; then
    "$XRAY_BIN" run -test -format json -config "$tmp" 2>&1 | tail -n 10 || true
    rm -f "$tmp"
    err "The generated Xray configuration was rejected."
    return 1
  fi
  mv -f "$tmp" "$XRAY_CFG" || { rm -f "$tmp"; return 1; }
  chown root:xray "$XRAY_CFG" || return 1
  chmod 640 "$XRAY_CFG" || return 1
  fix_log_perms
}



cfg_apply() {
  local tmp bak
  cfg_lock || return 1
  tmp=$(mktemp --suffix=.json "$XRAY_DIR/.config.new.XXXXXX") || { cfg_unlock; return 1; }
  bak=$(mktemp --suffix=.json "$XRAY_DIR/.config.bak.XXXXXX") || { rm -f "$tmp"; cfg_unlock; return 1; }
  if ! jq "$@" "$XRAY_CFG" > "$tmp"; then
    err "jq update failed; configuration unchanged."; rm -f "$tmp" "$bak"; cfg_unlock; return 1
  fi
  chmod 640 "$tmp" && chown root:xray "$tmp" || { rm -f "$tmp" "$bak"; cfg_unlock; return 1; }
  if ! validate_xray_config_file "$tmp"; then
    err "Xray rejected the new configuration; unchanged."
    "$XRAY_BIN" run -test -format json -config "$tmp" 2>&1 | tail -n 10 || true
    rm -f "$tmp" "$bak"; cfg_unlock; return 1
  fi
  cp -a "$XRAY_CFG" "$bak" || { err "Could not back up the Xray configuration."; rm -f "$tmp" "$bak"; cfg_unlock; return 1; }
  mv -f "$tmp" "$XRAY_CFG" || { rm -f "$tmp" "$bak"; cfg_unlock; return 1; }
  chown root:xray "$XRAY_CFG" || true
  chmod 640 "$XRAY_CFG" || true
  fix_log_perms
  if systemctl restart xray >/dev/null 2>&1 && wait_active xray 15; then
    rm -f "$bak"; cfg_unlock; return 0
  fi
  err "Xray restart failed; rolling back."
  journal_hint xray
  cp -a "$bak" "$XRAY_CFG" || true
  chown root:xray "$XRAY_CFG" || true
  chmod 640 "$XRAY_CFG" || true
  systemctl restart xray >/dev/null 2>&1 || true
  rm -f "$bak"; cfg_unlock
  return 1
}


# ── Xray Handler API (add/remove users without restart) ──────────────
xray_api_ready() {
  # Live (no-restart) user changes are OPT-IN: on Xray 26.x users added through the API were
  # accepted but then rejected on real connections (field report). Default = persist to disk
  # and restart Xray, which is reliable and also really ends sessions of removed users.
  # Set FINIXO_HOT_ADD=1 to use the API anyway.
  [ "${FINIXO_HOT_ADD:-0}" = 1 ] || return 1
  [ -x "$XRAY_BIN" ] || return 1
  ss -ltnH 2>/dev/null | gq -qE ":${XRAY_API_PORT:-10085}[[:space:]]" || return 1
  return 0
}

# The Xray API only blocks NEW connections: removing a user does not close the sessions it already has
# (verified on a real Xray). Ending sessions therefore takes a short Xray restart, and every client
# reconnects within seconds. Inside Connection Control batches the restart is queued and done ONCE.
CC_BATCH=0; CC_RESTART_PENDING=0
cc_flush_restart() {
  [ "${CC_RESTART_PENDING:-0}" = 1 ] || return 0
  CC_RESTART_PENDING=0
  info "Closing the sessions with ONE short Xray restart (every connected client reconnects within seconds)..."
  if systemctl restart xray >/dev/null 2>&1 && wait_active xray 15; then
    ok "Xray restarted — the sessions of the changed users are closed."
    return 0
  fi
  err "Xray restart failed."; journal_hint xray 2>/dev/null || true
  return 1
}

# Update config on disk only (no restart). Used before API hot-add/remove.
cfg_apply_disk() {
  local tmp bak
  cfg_lock || return 1
  tmp=$(mktemp --suffix=.json "$XRAY_DIR/.config.new.XXXXXX") || { cfg_unlock; return 1; }
  bak=$(mktemp --suffix=.json "$XRAY_DIR/.config.bak.XXXXXX") || { rm -f "$tmp"; cfg_unlock; return 1; }
  if ! jq "$@" "$XRAY_CFG" > "$tmp"; then
    err "jq update failed; configuration unchanged."; rm -f "$tmp" "$bak"; cfg_unlock; return 1
  fi
  chmod 640 "$tmp" && chown root:xray "$tmp" || { rm -f "$tmp" "$bak"; cfg_unlock; return 1; }
  if ! validate_xray_config_file "$tmp"; then
    err "Xray rejected the new configuration; unchanged."
    "$XRAY_BIN" run -test -format json -config "$tmp" 2>&1 | tail -n 10 || true
    rm -f "$tmp" "$bak"; cfg_unlock; return 1
  fi
  cp -a "$XRAY_CFG" "$bak" || { err "Could not back up the Xray configuration."; rm -f "$tmp" "$bak"; cfg_unlock; return 1; }
  mv -f "$tmp" "$XRAY_CFG" || { rm -f "$tmp" "$bak"; cfg_unlock; return 1; }
  chown root:xray "$XRAY_CFG" || true
  chmod 640 "$XRAY_CFG" || true
  rm -f "$bak"
  cfg_unlock
  return 0
}

# Hot-add a user via Xray API (no restart). Falls back to full restart on failure.
# Args: tag email secret protocol(vless|vmess|trojan)
xray_api_add_user() {
  local tag=$1 email=$2 secret=$3 proto=$4
  local srv="127.0.0.1:${XRAY_API_PORT:-10085}" tmp out rc=1
  xray_api_ready || return 1
  tmp=$(mktemp --suffix=.json /tmp/finixo-adu.XXXXXX) || return 1
  case "$proto" in
    vless)
      jq -nc --arg tag "$tag" --arg id "$secret" --arg email "$email" \
        '{inbounds:[{tag:$tag,port:1,protocol:"vless",settings:{clients:[{id:$id,email:$email,level:0}],decryption:"none"}}]}' > "$tmp" ;;
    vmess)
      jq -nc --arg tag "$tag" --arg id "$secret" --arg email "$email" \
        '{inbounds:[{tag:$tag,port:1,protocol:"vmess",settings:{clients:[{id:$id,alterId:0,email:$email,level:0}]}}]}' > "$tmp" ;;
    trojan)
      jq -nc --arg tag "$tag" --arg pw "$secret" --arg email "$email" \
        '{inbounds:[{tag:$tag,port:1,protocol:"trojan",settings:{clients:[{password:$pw,email:$email,level:0}]}}]}' > "$tmp" ;;
    *) rm -f "$tmp"; return 1 ;;
  esac
  # The CLI exits 0 even when nothing was added (e.g. config rejected, user exists):
  # trust only its "Added N user(s)" line, otherwise the caller falls back to a restart.
  out=$(timeout 10 "$XRAY_BIN" api adu --server="$srv" "$tmp" 2>&1) || true
  if grep -Eq 'Added [1-9][0-9]* user' <<< "$out"; then
    rc=0
  fi
  rm -f "$tmp"
  return $rc
}

# Hot-remove a user via Xray API (no restart).
# Args: tag email
xray_api_rm_user() {
  local tag=$1 email=$2
  local srv="127.0.0.1:${XRAY_API_PORT:-10085}"
  xray_api_ready || return 1
  # rmu also exits 0 when the user was not found / not removed: require "Removed N".
  local out
  out=$(timeout 10 "$XRAY_BIN" api rmu --server="$srv" -tag="$tag" "$email" 2>&1) || true
  grep -Eq 'Removed [1-9][0-9]* user' <<< "$out"
}

# Ensure existing config has API block (for upgrades / repair). Idempotent.
ensure_xray_api() {
  # Classic dokodemo-door API inbound (works on all Xray versions; used by Marzban/3x-ui)
  [ -f "$XRAY_CFG" ] || return 1
  local port="${XRAY_API_PORT:-10085}"
  if jq -e '.inbounds[]?|select(.tag=="api" and .protocol=="dokodemo-door")' "$XRAY_CFG" >/dev/null 2>&1 \
     && jq -e '.api.services[]?|select(.=="HandlerService")' "$XRAY_CFG" >/dev/null 2>&1; then
    return 0
  fi
  info "Enabling Xray Handler API on 127.0.0.1:${port} (one-time restart)..."
  local tmp
  tmp=$(mktemp --suffix=.json "$XRAY_DIR/.config.api.XXXXXX") || return 1
  if ! jq --argjson port "$port" '
    .stats = (.stats // {})
    | .api = {"tag":"api","services":["HandlerService","StatsService"]}
    | .policy = (.policy // {
        "levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true}},
        "system": {"statsInboundUplink": true, "statsInboundDownlink": true}
      })
    | .inbounds = (
        ([.inbounds[]? | select(.tag != "api")])
        + [{"tag":"api","listen":"127.0.0.1","port":$port,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}}]
      )
    | .routing = (.routing // {"domainStrategy":"AsIs","rules":[]})
    | .routing.rules = (
        [{"type":"field","inboundTag":["api"],"outboundTag":"api"}]
        + ((.routing.rules // []) | map(select((.inboundTag // []) != ["api"])))
      )
  ' "$XRAY_CFG" > "$tmp"; then
    rm -f "$tmp"; return 1
  fi
  chmod 640 "$tmp" && chown root:xray "$tmp" 2>/dev/null || chown root:root "$tmp"
  if command -v validate_xray_config_file >/dev/null 2>&1; then
    validate_xray_config_file "$tmp" || { rm -f "$tmp"; return 1; }
  elif [ -x "$XRAY_BIN" ]; then
    "$XRAY_BIN" run -test -format json -config "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; return 1; }
  fi
  mv -f "$tmp" "$XRAY_CFG"
  chown root:xray "$XRAY_CFG" 2>/dev/null || true
  chmod 640 "$XRAY_CFG"
  systemctl restart xray >/dev/null 2>&1 && wait_active xray 15
}


do_update_xray_inner() {
  is_installed || { err "Not installed."; return 1; }
  need_root
  local tmp bakdir
  bakdir=$(mktemp -d "$WORK_DIR/xray-update.XXXXXX") || return 1
  cp -a "$XRAY_BIN" "$bakdir/xray" || { rm -rf "$bakdir"; err "Could not back up the Xray binary."; return 1; }
  [ -f "$XRAY_ASSET/geoip.dat" ] && cp -a "$XRAY_ASSET/geoip.dat" "$bakdir/geoip.dat"
  [ -f "$XRAY_ASSET/geosite.dat" ] && cp -a "$XRAY_ASSET/geosite.dat" "$bakdir/geosite.dat"
  tmp=$(xray_download_staging) || { rm -rf "$bakdir"; return 1; }
  if ! XRAY_LOCATION_ASSET="$tmp/x" "$tmp/x/xray" run -test -format json -config "$XRAY_CFG" >/dev/null 2>&1; then
    err "The new Xray rejects the current configuration; update cancelled (nothing changed)."
    rm -rf "$tmp" "$bakdir"; return 1
  fi
  if ! install_xray "$tmp"; then
    rm -rf "$tmp"
    { cp -a "$bakdir/xray" "${XRAY_BIN}.rb" && mv -f "${XRAY_BIN}.rb" "$XRAY_BIN"; } || true
    rm -rf "$bakdir"; return 1
  fi
  rm -rf "$tmp"
  if systemctl restart xray >/dev/null 2>&1 && wait_active xray 15; then
    rm -rf "$bakdir"; ok "Xray updated."; return 0
  fi
  err "Xray failed after the update; rolling back."
  journal_hint xray
  { cp -a "$bakdir/xray" "${XRAY_BIN}.rb" && mv -f "${XRAY_BIN}.rb" "$XRAY_BIN"; } || true
  [ -f "$bakdir/geoip.dat" ] && cp -a "$bakdir/geoip.dat" "$XRAY_ASSET/geoip.dat"
  [ -f "$bakdir/geosite.dat" ] && cp -a "$bakdir/geosite.dat" "$XRAY_ASSET/geosite.dat"
  rm -rf "$bakdir"
  systemctl restart xray >/dev/null 2>&1 || true
  return 1
}

# ----------------------------------------------------------------------------
# SSH bridge
# ----------------------------------------------------------------------------
write_hold_script() {
  local rc
  write_atomic_from_stdin "$HOLD" 755 <<'EOF2'
#!/bin/sh
# Tunnel-only SSH sessions execute this command through ForceCommand.
# cat exits on EOF when the client closes the session (no orphan sleep processes).
exec cat >/dev/null
EOF2
  rc=$?; [ "$rc" -le 1 ] || return 2
  [ -x "$HOLD" ] || return 2
  return "$rc"
}

write_bridge_py() {
  local rc
  write_atomic_from_stdin "$BRIDGE" 755 <<'PYEOF'
#!/usr/bin/env python3
"""FinixoGate SSH-over-HTTP-Upgrade raw TCP bridge.

Not RFC 6455 framing: after HTTP 101 the connection is a raw bidirectional
TCP stream for SSH-over-Upgrade clients (HTTP Injector / HTTP Custom style).
"""
import asyncio
import os
import socket
import sys
import time

DEBUG = os.environ.get("FINIXO_BRIDGE_DEBUG") == "1"
_last_log = {}


def log_once(key, msg, every=15.0):
    """Errors only, and at most one line per key every `every` seconds (no journal spam)."""
    now = time.monotonic()
    if now - _last_log.get(key, -1e9) >= every:
        _last_log[key] = now
        print(msg, file=sys.stderr, flush=True)


LISTEN_PORT = int(sys.argv[1])
TARGET_PORT = int(sys.argv[2])
EXPECTED_PATH = sys.argv[3]
TARGET = ("127.0.0.1", TARGET_PORT)
MAX_HEADER = 16384
READ_CHUNK = 4096
RESP_101 = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n\r\n"
)
RESP_400 = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
RESP_502 = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def close_writer(writer):
    try:
        writer.close()
    except Exception:
        pass


def split_headers(buf: bytes):
    idx = buf.find(b"\r\n\r\n")
    if idx >= 0:
        end = idx + 4
        return bytes(buf[:end]), bytes(buf[end:])
    idx = buf.find(b"\n\n")
    if idx >= 0:
        end = idx + 2
        return bytes(buf[:end]), bytes(buf[end:])
    return None


def parse_request(head: bytes):
    """Lenient on purpose: remote proxies/CDNs rewrite or strip Upgrade,
    Connection and Sec-WebSocket-* headers. This port is 127.0.0.1-only and
    Nginx routes only the SSH path here, so accept any HTTP request line."""
    try:
        lines = head.replace(b"\r\n", b"\n").split(b"\n")
        first = lines[0].decode("latin1").strip()
        parts = first.split()
        if len(parts) < 2 or not parts[-1].upper().startswith("HTTP/"):
            return None
        # Path is enforced by Nginx location; accept anything that reached us.
        headers = {}
        for raw in lines[1:]:
            if not raw or b":" not in raw:
                continue
            k, v = raw.split(b":", 1)
            headers[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()
        if DEBUG:
            print("ssh-ws req: %s | headers=%s" % (first[:160], ",".join(sorted(headers))), file=sys.stderr, flush=True)
        return {"key": headers.get("sec-websocket-key", "")}
    except Exception:
        return None


def build_101(req):
    import base64, hashlib
    out = (b"HTTP/1.1 101 Switching Protocols\r\n"
           b"Upgrade: websocket\r\n"
           b"Connection: Upgrade\r\n")
    key = req.get("key", "") if isinstance(req, dict) else ""
    if key:
        acc = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        out += ("Sec-WebSocket-Accept: %s\r\n" % acc).encode()
    return out + b"\r\n"


async def read_headers(reader):
    buf = bytearray()
    while True:
        if len(buf) >= MAX_HEADER:
            raise ValueError("header too large")
        chunk = await asyncio.wait_for(reader.read(READ_CHUNK), 10)
        if not chunk:
            raise EOFError
        buf.extend(chunk)
        parts = split_headers(bytes(buf))
        if parts is not None:
            return parts


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, ConnectionAbortedError):
        pass
    except Exception as exc:
        log_once("pipe", f"pipe error: {exc}")
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
                await writer.drain()
            else:
                close_writer(writer)
        except Exception:
            close_writer(writer)


async def handle(cr, cw):
    try:
        sock = cw.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass
    try:
        head, leftover = await read_headers(cr)
    except Exception:
        close_writer(cw)
        return
    req = parse_request(head)
    if not req:
        try:
            cw.write(RESP_400)
            await cw.drain()
        except Exception:
            pass
        close_writer(cw)
        return
    try:
        sr, sw = await asyncio.wait_for(asyncio.open_connection(*TARGET), 5)
    except Exception as exc:
        log_once("sshd", f"sshd connect failed: {exc}")
        try:
            cw.write(RESP_502)
            await cw.drain()
        except Exception:
            pass
        close_writer(cw)
        return
    try:
        cw.write(build_101(req))
        await cw.drain()
        if leftover:
            sw.write(leftover)
            await sw.drain()
        await asyncio.gather(pipe(cr, sw), pipe(sr, cw))
    except Exception as exc:
        log_once("tunnel", f"tunnel error: {exc}")
    finally:
        close_writer(sw)
        close_writer(cw)


async def main():
    print(f"FinixoGate SSH bridge 127.0.0.1:{LISTEN_PORT} -> 127.0.0.1:{TARGET_PORT} path={EXPECTED_PATH}",
          file=sys.stderr, flush=True)
    server = await asyncio.start_server(handle, "127.0.0.1", LISTEN_PORT, limit=65536, backlog=2048)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
PYEOF
  rc=$?; [ "$rc" -le 1 ] || return 2
  [ -x "$BRIDGE" ] || return 2
  return "$rc"
}

write_bridge_unit() {
  local sp=$1 rc
  id finixo-bridge >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin finixo-bridge || return 2
  write_atomic_from_stdin /etc/systemd/system/finixo-ssh-ws.service 644 <<EOF2
[Unit]
Description=FinixoGate SSH-over-HTTP-Upgrade bridge
After=network-online.target ssh.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
User=finixo-bridge
Group=finixo-bridge
WorkingDirectory=/
ExecStart=/usr/bin/python3 -u $BRIDGE $P_SSHWS $sp $WSP_SSH
Restart=always
RestartSec=2
TimeoutStopSec=8
LimitNOFILE=65536
MemoryMax=512M
OOMScoreAdjust=-150
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectProc=invisible
LockPersonality=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_INET AF_UNIX
IPAddressAllow=localhost
IPAddressDeny=any
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
SyslogIdentifier=finixo-ssh-ws

[Install]
WantedBy=multi-user.target
EOF2
  rc=$?; [ "$rc" -le 1 ] || return 2
  if [ "$rc" -eq 0 ]; then systemctl daemon-reload || return 2; fi
  return "$rc"
}

ssh_users() {
  local gid members
  gid=$(getent group "$SSH_GROUP" 2>/dev/null | cut -d: -f3)
  [ -n "$gid" ] || return 0
  members=$(getent group "$SSH_GROUP" 2>/dev/null | cut -d: -f4-)
  {
    awk -F: -v g="$gid" '$4==g{print $1}' /etc/passwd
    if [ -n "$members" ]; then tr ',' '\n' <<< "$members"; fi
  } | sed '/^$/d' | sort -u
}

migrate_tunnel_shells() {
  local u sh
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    # Only repair a broken (nologin/false/empty) shell; never override a deliberately chosen one.
    sh=$(getent passwd "$u" | cut -d: -f7)
    case $sh in ""|*/nologin|*/false) usermod -s /bin/bash "$u" 2>/dev/null || true ;; esac
  done < <(ssh_users)
}

# ----------------------------------------------------------------------------
# SSH login banner — shown by HTTP Custom & co. as "Server Message" after a
# successful connect (HTML: <font color>, <b>, <big>, <br>, centered block).
# Brand / contact / tagline live in $BANNER_CONF and can be edited from the SSH menu.
# ----------------------------------------------------------------------------
banner_esc() { printf '%s' "$1" | tr -d '\r\n' | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
banner_get() { [ -r "$BANNER_CONF" ] && sed -n "s/^$1=//p" "$BANNER_CONF" | head -n1; return 0; }
write_ssh_banner() {
  local brand contact tag line
  brand=$(banner_get BRAND);   brand=${brand:-finixo}
  tag=$(banner_get TAGLINE);   tag=${tag:-Fast · Stable · Private}
  contact=$(banner_get CONTACT)
  brand=$(banner_esc "$brand"); tag=$(banner_esc "$tag"); contact=$(banner_esc "$contact")
  install -d -m 755 "$CONF_DIR" 2>/dev/null || true
  line='<font color="#FF2D55"><b>━━━━━━━━━━━━━━━━━━━━━━━━</b></font>'
  {
    printf '%s' '<div align="center" style="text-align:center">'
    printf '<br>%s<br><br>' "$line"
    printf '%s<br>' '<font color="#FFFFFF">🚀 Welcome to 🚀</font>'
    printf '<font color="#1E90FF"><big><big><big><b>%s</b></big></big></big></font><br><br>' "$brand"
    printf '%s<br><br>' '<font color="#FF2D55">Premium Secure Tunnel</font>'
    printf '<font color="#FFC107">%s</font><br><br>' "$tag"
    printf '%s<br><br>' '<font color="#00E676">✅ Connected successfully</font>'
    printf '%s<br><br>' '<font color="#FF8A65">Please respect the fair-use rules 🤝</font>'
    printf '%s<br><br>' "$line"
    [ -z "$contact" ] || printf '<font color="#40C4FF">🔗 %s</font><br><br>' "$contact"
    printf '<font color="#82B1FF">Made with 💙 by %s</font><br>' "$brand"
    printf '%s\n' '</div>'
  } | write_atomic_from_stdin "$BANNER_FILE" 644
  local rc=$?
  [ "$rc" -le 1 ]
}
ssh_banner_edit() {
  local b c t cb cc ct
  cb=$(banner_get BRAND); cc=$(banner_get CONTACT); ct=$(banner_get TAGLINE)
  echo -e "  ${D}Shown inside the client after a successful SSH connect. Enter = keep current.${N}\n"
  read -r -p "  Brand name [${cb:-finixo}]: " b || return 0
  read -r -p "  Tagline [${ct:-Fast · Stable · Private}]: " t || return 0
  read -r -p "  Contact line (Telegram etc., empty = hide) [${cc:-none}]: " c || return 0
  b=${b:-${cb:-finixo}}; t=${t:-${ct:-Fast · Stable · Private}}
  case $c in "") c=$cc ;; "-"|none) c="" ;; esac
  install -d -m 755 "$CONF_DIR" 2>/dev/null || true
  printf 'BRAND=%s\nTAGLINE=%s\nCONTACT=%s\n' "$(printf '%s' "$b" | tr -d '\r\n')" "$(printf '%s' "$t" | tr -d '\r\n')" "$(printf '%s' "$c" | tr -d '\r\n')" > "$BANNER_CONF"
  chmod 644 "$BANNER_CONF"
  if write_ssh_banner; then ok "Banner updated — it appears on the next connection (no restart needed)."
  else err "Could not write the banner."; fi
}

write_ssh_dropin_content() {
  # LoginGraceTime is global-only in sshd_config(5); ClientAlive* are also valid in Match but are kept global here.
  cat <<EOF2
# FinixoGate tunnel-only SSH users.
# All public SSH-WS sessions reach sshd through 127.0.0.1 bridge connections.
MaxStartups $SSH_MAXSTARTUPS
LoginGraceTime 20
ClientAliveInterval 30
ClientAliveCountMax 6
EOF2
  if sshd -T 2>/dev/null | gq -qi '^persourcepenalties'; then
    echo "PerSourcePenaltyExemptList 127.0.0.1,::1"
  fi
  cat <<EOF2

Match Group $SSH_GROUP
    PasswordAuthentication yes
    KbdInteractiveAuthentication yes
    PubkeyAuthentication no
    PermitEmptyPasswords no
    ForceCommand $HOLD
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    AllowTcpForwarding $SSH_TCP_FORWARDING
    AllowStreamLocalForwarding no
    PermitTunnel no
    GatewayPorts no
    PermitUserRC no
    MaxSessions 20
    MaxAuthTries 3
EOF2
  # Banner only when the file exists (avoids an sshd -t failure on a missing path).
  # Indented so it sits explicitly INSIDE the Match block above (valid there; applies to tunnel users).
  if [ -s "$BANNER_FILE" ]; then
    printf '    Banner %s\n' "$BANNER_FILE"
  fi
}

setup_ssh() {
  validate_ssh_maxstartups || { err "Invalid SSH_MAXSTARTUPS='$SSH_MAXSTARTUPS' (start:rate:full)."; return 1; }
  validate_ssh_forwarding || { err "Invalid SSH_TCP_FORWARDING='$SSH_TCP_FORWARDING' (local or yes)."; return 1; }
  init_work_dir || return 1
  getent group "$SSH_GROUP" >/dev/null 2>&1 || groupadd "$SSH_GROUP" || return 1
  install -d -m 755 /etc/ssh/sshd_config.d "$LOCK_DIR" || return 1
  # Needed before sshd -T / write_ssh_dropin_content (PerSourcePenaltyExemptList etc.)
  install -d -m 755 /run/sshd 2>/dev/null || true

  local main_backup dropin_backup tmp="" had=0 include_added=0 rc=0
  main_backup="$WORK_DIR/sshd_config.bak"; dropin_backup="$WORK_DIR/finixo.conf.bak"
  rm -f "$main_backup" "$dropin_backup"
  cp -a /etc/ssh/sshd_config "$main_backup" || return 1
  if [ -f "$SSH_DROPIN" ]; then cp -a "$SSH_DROPIN" "$dropin_backup"; had=1
  elif [ -f "$SSH_LEGACY_DROPIN" ]; then cp -a "$SSH_LEGACY_DROPIN" "$dropin_backup"; had=1; fi

  if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
    if sed -i '1i# FinixoGate managed sshd_config.d include.\nInclude /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config; then include_added=1; else rc=1; fi
  fi
  write_ssh_banner || warn "Could not write the SSH banner (continuing without it)."
  if [ "$rc" -eq 0 ]; then tmp=$(mktemp "$WORK_DIR/sshdropin.XXXXXX") || rc=1; fi
  if [ "$rc" -eq 0 ]; then write_ssh_dropin_content > "$tmp" || rc=1; fi
  if [ "$rc" -eq 0 ]; then install -m 644 "$tmp" "$SSH_DROPIN" || rc=1; fi
  [ -z "$tmp" ] || rm -f "$tmp"
  if [ "$rc" -eq 0 ]; then
    if ! sshd -t 2>/dev/null; then err "sshd rejected the FinixoGate configuration; rolling back."; sshd -t || true; rc=1; fi
  fi
  if [ "$rc" -eq 0 ] && ! reload_ssh; then err "Could not reload sshd; restoring the previous SSH configuration."; rc=2; fi

  if [ "$rc" -ne 0 ]; then
    cp -a "$main_backup" /etc/ssh/sshd_config || true
    rm -f "$SSH_DROPIN" "$SSH_LEGACY_DROPIN"
    if [ "$had" -eq 1 ]; then cp -a "$dropin_backup" "$SSH_DROPIN" || true; fi
    [ "$rc" -eq 2 ] && { sshd -t >/dev/null 2>&1 && reload_ssh || true; }
    rm -f "$main_backup" "$dropin_backup"
    return 1
  fi
  [ "$include_added" -eq 1 ] && printf '1\n' > "$SSH_INCLUDE_MARKER"
  rm -f "$SSH_LEGACY_DROPIN"
  migrate_tunnel_shells
  if sshd -T 2>/dev/null | gq -Eiq '^(allowusers|allowgroups) '; then
    warn "sshd has AllowUsers/AllowGroups set: allow group '$SSH_GROUP' or tunnel users will be rejected."
  fi
  rm -f "$main_backup" "$dropin_backup"
  return 0
}


# Migrate SSH-WS path to short /ssh-ws (fixes HTTP Custom payload mismatches)
migrate_ssh_path() {
  load_conf
  local newp=${1:-/ssh-ws}
  validate_ws_path "$newp" || { err "Invalid path $newp"; return 1; }
  # Conflict with other protocols?
  for p in "$WSP_VLESS" "$WSP_VMESS" "$WSP_TROJAN" "$WSP_SS"; do
    [ "$p" = "$newp" ] && { err "Path $newp already used by another protocol"; return 1; }
  done
  WSP_SSH=$newp
  write_client_profile || return 1
  # Update Xray is N/A for SSH; rewrite nginx + bridge
  setup_bridge || return 1
  write_nginx_full || return 1
  ok "SSH-WS path is now: $WSP_SSH"
  ssh_info
}

setup_bridge() {
  load_conf
  [ -n "${WSP_SSH:-}" ] || { err "The SSH WebSocket path is missing."; return 1; }
  local hold_rc bridge_rc unit_rc sp changed=0
  write_hold_script; hold_rc=$?
  [ "$hold_rc" -le 1 ] || { err "Could not write $HOLD"; return 1; }
  write_bridge_py; bridge_rc=$?
  [ "$bridge_rc" -le 1 ] || { err "Could not write $BRIDGE"; return 1; }
  sp=$(ssh_port) || return 1
  write_bridge_unit "$sp"; unit_rc=$?
  [ "$unit_rc" -le 1 ] || { err "Could not write the finixo-ssh-ws unit"; return 1; }
  [ "$hold_rc" -eq 0 ] && changed=1
  [ "$bridge_rc" -eq 0 ] && changed=1
  [ "$unit_rc" -eq 0 ] && changed=1
  systemctl enable finixo-ssh-ws >/dev/null 2>&1 || return 1
  if [ "$changed" -eq 1 ] || ! systemctl is-active --quiet finixo-ssh-ws; then
    systemctl restart finixo-ssh-ws >/dev/null 2>&1 || return 1
  fi
  wait_active finixo-ssh-ws 15
}

# ----------------------------------------------------------------------------
# Nginx (self-signed TLS, answers ANY SNI and ANY Host header)
# ----------------------------------------------------------------------------
ngx_v6() { [ "${FINIXO_DISABLE_IPV6:-1}" = 1 ] && return 1; [ -s /proc/net/if_inet6 ]; }

write_nginx_rate_zone() {
  # Default: no request/conn limits on VPN paths (NGX_LIMIT_*=0).
  local rc
  write_atomic_from_stdin "$NGX_RATE" 644 <<EOF2
# Finixo — WebSocket Connection map (no client rate limits by default)
# Kept for compatibility; WS locations hardcode Connection "upgrade"
map \$http_upgrade \$finixo_connection {
    default      upgrade;
    ''           close;
    ~*websocket  upgrade;
}
map \$http_upgrade \$finixo_upgrade {
    default      \$http_upgrade;
    ''           '';
}
EOF2
  rc=$?; [ "$rc" -le 1 ]
}

# HTTP-context performance knobs (safe inside conf.d)

write_ws_logrotate() {
  write_atomic_from_stdin /etc/logrotate.d/finixo-ws 644 <<'EOF2'
/var/log/nginx/finixo-ws.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 "$(cat /run/nginx.pid)" 2>/dev/null || true
    endscript
}
EOF2
}

# nginx -T output without FinixoGate's own files, so "already defined elsewhere" checks are accurate.
ngx_dump_others() {
  nginx -T 2>/dev/null | awk '/^# configuration file /{skip=($0 ~ /finixo/)} !skip' || true
}
ngx_defined_elsewhere() {   # directive name -> 0 if some non-Finixo file already sets it
  grep -qE "^[[:space:]]*$1([[:space:];]|\$)" <<< "${NGX_DUMP_CACHE:-}"
}

write_nginx_perf() {
  # Each directive is written ONLY if nginx does not already define it elsewhere
  # (a duplicate in http{} is fatal: "directive is duplicate").
  local dump line name body
  body='# Finixo Gate — high-throughput HTTP tuning (included in http{})'$'\n'
  body+='log_format finixo_ws '"'"'$remote_addr $time_iso8601 $request_uri $status $http_upgrade'"'"';'$'\n'
  rm -f "$NGX_PERF"
  dump=$(ngx_dump_others)
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    name=${line%%[[:space:]]*}
    if grep -qE "^[[:space:]]*${name}[[:space:]]" <<< "$dump"; then continue; fi
    body+="$line"$'\n'
  done <<'EOF2'
underscores_in_headers on;
proxy_buffer_size 16k;
proxy_buffers 64 16k;
proxy_busy_buffers_size 64k;
proxy_headers_hash_max_size 1024;
proxy_headers_hash_bucket_size 128;
variables_hash_max_size 2048;
variables_hash_bucket_size 128;
open_file_cache max=20000 inactive=60s;
open_file_cache_valid 60s;
open_file_cache_min_uses 2;
open_file_cache_errors on;
EOF2
  printf '%s' "$body" | write_atomic_from_stdin "$NGX_PERF" 644
  # Best-effort: raise worker_connections in main nginx.conf when present
  if [ -f /etc/nginx/nginx.conf ]; then
    sed -i -E 's/worker_connections[[:space:]]+[0-9]+;/worker_connections 65535;/' /etc/nginx/nginx.conf 2>/dev/null || true
    if ! grep -qE 'worker_rlimit_nofile' /etc/nginx/nginx.conf 2>/dev/null; then
      sed -i '/^worker_processes/a worker_rlimit_nofile 65535;' /etc/nginx/nginx.conf 2>/dev/null || true
    fi
    # After a reload, old workers that still carry long WebSocket tunnels are retired after 1 h
    # (otherwise they pile up and keep their memory forever).
    if ! grep -qE '^[[:space:]]*worker_shutdown_timeout' /etc/nginx/nginx.conf 2>/dev/null; then
      sed -i '/^worker_processes/a worker_shutdown_timeout 1h;' /etc/nginx/nginx.conf 2>/dev/null || true
    fi
    if ! grep -qE '^[[:space:]]*multi_accept[[:space:]]+on' /etc/nginx/nginx.conf 2>/dev/null; then
      sed -i '/events[[:space:]]*{/a\    multi_accept on;' /etc/nginx/nginx.conf 2>/dev/null || true
    fi
  fi
  return 0
}

nginx_default_conflict() {
  command -v nginx >/dev/null 2>&1 || return 1
  nginx -T 2>/dev/null | awk -v self="$NGX_CONF" '
    /^# configuration file / { file=$0; sub(/^# configuration file /,"",file); sub(/:$/,"",file); next }
    /^[[:space:]]*listen[[:space:]]+/ {
      sub(/#.*$/, "")
      if ($0 ~ /default_server/) {
        tok=$2; sub(/;$/,"",tok)
        if (tok ~ /(^|:)(80|443)$/ && file != self) found=1
      }
    }
    END { exit(found ? 0 : 1) }
  '
}

ws_location() {
  # WebSocket reverse-proxy → localhost Xray/SSH-bridge.
  # Compatible with ANY remote proxy / CDN that forwards Upgrade:
  #  - Connection always "upgrade" (not map-dependent — remote proxies often
  #    strip or rewrite Connection; hardcoding is what Marzban/3x-ui/x-ui use)
  #  - Upgrade passed through as-is ($http_upgrade)
  #  - No "if (!websocket) return 404" — that blocked 101 behind many CDNs
  #  - ^~ prefix match (exact = broke some encoded/proxy path variants)
  #  - Long timeouts for mobile networks
  local path=$1 port=$2
  cat <<EOF2

location ^~ $path {
    access_log off;   # no per-connection log: the online counter now uses Xray stats + live sshd sessions
    proxy_pass http://127.0.0.1:$port;
    proxy_http_version 1.1;
    proxy_redirect off;
    # --- critical for 101 Switching Protocols behind remote proxy ---
    proxy_set_header Upgrade "websocket";
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    # Real peer IP, overwritten (a client cannot fake it) — Xray reads it for the live online counter
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
    # Long-lived tunnels (mobile / high-latency remote proxies)
    proxy_connect_timeout 60s;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    proxy_socket_keepalive on;
    # Zero-copy WS frames
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_max_temp_file_size 0;
    proxy_cache off;
    proxy_store off;
    proxy_buffer_size 16k;
    proxy_busy_buffers_size 32k;
    tcp_nodelay on;
    tcp_nopush off;
    sendfile on;
    # Do not force gzip on binary tunnel
    gzip off;
}
EOF2
}

ngx_snapshot() {
  local snap=$1 f
  for f in "$NGX_CONF" "$NGX_RATE" "$NGX_PERF" "$NGX_STEALTH" "$NGX_WS"; do
    if [ -f "$f" ]; then cp -a "$f" "$snap/$(basename "$f")"; fi
  done
  return 0
}
ngx_rollback() {
  local snap=$1 f b
  for f in "$NGX_CONF" "$NGX_RATE" "$NGX_PERF" "$NGX_STEALTH" "$NGX_WS"; do
    b="$snap/$(basename "$f")"
    if [ -f "$b" ]; then cp -a "$b" "$f"; else rm -f "$f"; fi
  done
}



# ----------------------------------------------------------------------------
# Nginx stealth + stability boost
# ----------------------------------------------------------------------------
ngx_headers_more() {
  nginx -V 2>&1 | gq -qi 'headers-more' && return 0
  ls /etc/nginx/modules-enabled/ 2>/dev/null | gq -qi 'headers-more' && return 0
  # Skip apt retries for 24h after a failure (offline / lock); then allow retry
  if [ -f "$CONF_DIR/.no-headers-more" ]; then
    local _age=999999 _now _then
    _now=$(date +%s 2>/dev/null || echo 0)
    _then=$(stat -c %Y "$CONF_DIR/.no-headers-more" 2>/dev/null || echo 0)
    _age=$((_now - _then))
    [ "$_age" -lt 86400 ] && return 1
    rm -f "$CONF_DIR/.no-headers-more" 2>/dev/null || true
  fi
  command -v apt-get >/dev/null 2>&1 || return 1
  if ! DEBIAN_FRONTEND=noninteractive timeout 60 apt-get install -y libnginx-mod-http-headers-more-filter >/dev/null 2>&1; then
    mkdir -p "$CONF_DIR" 2>/dev/null || true
    : > "$CONF_DIR/.no-headers-more" 2>/dev/null || true
    return 1
  fi
  rm -f "$CONF_DIR/.no-headers-more" 2>/dev/null || true
  ls /etc/nginx/modules-enabled/ 2>/dev/null | gq -qi 'headers-more'
}
write_nginx_stealth() {
  local body="# Finixo Gate — fingerprint hiding (http{} level)
"
  rm -f "$NGX_STEALTH"
  NGX_DUMP_CACHE=$(ngx_dump_others)
  ngx_defined_elsewhere server_tokens || body+="server_tokens off;
"
  if ngx_headers_more; then
    NGX_DUMP_CACHE=$(ngx_dump_others)
    ngx_defined_elsewhere 'more_clear_headers[[:space:]]+Server;?' || body+="more_clear_headers Server;
"
    ngx_defined_elsewhere 'more_clear_headers[[:space:]]+X-Powered-By;?' || body+="more_clear_headers X-Powered-By;
"
  fi
  printf '%s' "$body" | write_atomic_from_stdin "$NGX_STEALTH" 644
  return 0
}
install_site_extras() {
  install -d -m 755 "$SITE_ROOT" || return 0
  # Always ensure non-empty decoy error pages (stealth); do not rely on nginx defaults
  if [ ! -s "$SITE_ROOT/404.html" ]; then
    cat > "$SITE_ROOT/404.html" <<'EOF2'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Page not found</title><style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:14vh auto;color:#222;padding:0 1.2rem;line-height:1.5}</style></head><body><h1>Page not found</h1><p>The page you requested could not be found.</p></body></html>
EOF2
  fi
  if [ ! -s "$SITE_ROOT/50x.html" ]; then
    cat > "$SITE_ROOT/50x.html" <<'EOF2'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Temporarily unavailable</title><style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:14vh auto;color:#222;padding:0 1.2rem;line-height:1.5}</style></head><body><h1>Temporarily unavailable</h1><p>We are working on it. Please try again in a few minutes.</p></body></html>
EOF2
  fi
  [ -f "$SITE_ROOT/robots.txt" ] || printf 'User-agent: *
Disallow:
' > "$SITE_ROOT/robots.txt"
  chmod 644 "$SITE_ROOT"/404.html "$SITE_ROOT"/50x.html "$SITE_ROOT"/robots.txt 2>/dev/null || true
  return 0
}
nginx_boost_system() {
  local changed=0 want
  want='[Unit]
StartLimitIntervalSec=0

[Service]
LimitNOFILE=1048576
Restart=always
RestartSec=2
OOMScoreAdjust=-200
'
  install -d -m 755 "$(dirname "$NGX_SYSD")" 2>/dev/null || return 0
  if [ "$(cat "$NGX_SYSD" 2>/dev/null)" != "${want%$'\n'}" ]; then printf '%s' "$want" > "$NGX_SYSD"; changed=1; fi
  if [ -f /etc/nginx/nginx.conf ]; then
    if grep -qE '^[[:space:]]*worker_rlimit_nofile' /etc/nginx/nginx.conf; then
      sed -i -E 's/^([[:space:]]*worker_rlimit_nofile)[[:space:]]+[0-9]+;/\1 262144;/' /etc/nginx/nginx.conf 2>/dev/null || true
    fi
    grep -qE '^[[:space:]]*worker_cpu_affinity' /etc/nginx/nginx.conf 2>/dev/null || \
      sed -i '/^worker_processes/a worker_cpu_affinity auto;' /etc/nginx/nginx.conf 2>/dev/null || true
    grep -qE '^[[:space:]]*accept_mutex' /etc/nginx/nginx.conf 2>/dev/null || \
      sed -i '/events[[:space:]]*{/a\    accept_mutex off;' /etc/nginx/nginx.conf 2>/dev/null || true
  fi
  [ "$changed" = 1 ] && systemctl daemon-reload >/dev/null 2>&1
  return 0
}

# ----------------------------------------------------------------------------
# HAProxy edge (public 80/443)  ·  Nginx core (localhost site + optional WS)
# Roles:
#   HAProxy — TLS terminate, maxconn, path route, timeout tunnel 24h, TFO
#   Nginx   — static decoy + ACME webroot on 127.0.0.1 only (when edge=haproxy)
#             OR full public WS stack (when FINIXO_EDGE=nginx)
# ----------------------------------------------------------------------------
haproxy_pem_refresh() {
  [ -f "$TLS_CRT" ] && [ -f "$TLS_KEY" ] || return 1
  install -d -m 700 "$TLS_DIR" 2>/dev/null || true
  local tmp
  tmp=$(mktemp "$TLS_DIR/.haproxy.pem.XXXXXX") || return 1
  if ! { cat "$TLS_CRT"; echo; cat "$TLS_KEY"; echo; } > "$tmp"; then
    rm -f "$tmp"; return 1
  fi
  if ! grep -q "BEGIN CERTIFICATE" "$tmp" || ! grep -q "BEGIN .*PRIVATE KEY" "$tmp"; then
    rm -f "$tmp"; return 1
  fi
  chmod 600 "$tmp" || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$HAP_PEM" || { rm -f "$tmp"; return 1; }
  return 0
}


# After Nginx switches from public :80/:443 to localhost-only, old workers may still
# hold the public ports until worker_shutdown_timeout. HAProxy cannot bind until free.
release_public_http_ports() {
  local i owner
  # Restart nginx so only the new (localhost) config is live — avoids 1h worker linger
  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl restart nginx >/dev/null 2>&1 || true
  fi
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    # exit 0 = still busy (non-haproxy holds 80/443); exit 1 = free
    if ! ss -tlnp 2>/dev/null | awk '
      $1=="LISTEN" && ($4 ~ /:80$/ || $4 ~ /:443$/) {
        if ($0 !~ /haproxy/) busy=1
      }
      END { exit busy ? 0 : 1 }'
    then
      return 0
    fi
    sleep 0.5
  done
  # Last resort: stop nginx briefly, free ports, start again (localhost binds only)
  warn "Public 80/443 still held after nginx restart — brief stop to free ports for HAProxy"
  systemctl stop nginx >/dev/null 2>&1 || true
  sleep 1
  # kill only nginx workers still on 80/443
  local pids
  pids=$(ss -tlnp 2>/dev/null | awk '/:80|:443/ && /nginx/ {while (match($0,/pid=[0-9]+/)) {print substr($0,RSTART+4,RLENGTH-4); $0=substr($0,RSTART+RLENGTH)}}' | sort -u)
  for p in $pids; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 1
  systemctl start nginx >/dev/null 2>&1 || true
  if ss -tlnp 2>/dev/null | awk '
      $1=="LISTEN" && ($4 ~ /:80$/ || $4 ~ /:443$/) { if ($0 !~ /haproxy/) busy=1 }
      END { exit busy ? 0 : 1 }'
  then
    err "Could not free public 80/443 for HAProxy (another process holds them)"
    return 1
  fi
  return 0
}

write_haproxy_full() {
  load_conf
  choose_ws_paths || return 1
  haproxy_pem_refresh || { err "Cannot build HAProxy PEM from TLS files"; return 1; }
  install -d -m 755 /etc/haproxy /etc/systemd/system/haproxy.service.d /run/haproxy 2>/dev/null || true
  chgrp haproxy /run/haproxy 2>/dev/null || true
  # Prefer non-root workers when the distro user exists
  HAP_USER_LINE=""
  if getent passwd haproxy >/dev/null 2>&1; then HAP_USER_LINE="    user haproxy"; fi
  if getent group haproxy >/dev/null 2>&1; then HAP_USER_LINE="${HAP_USER_LINE}
    group haproxy"; fi

  # Binds: TFO when kernel allows; IPv6 only when available
  local tfo="" v6=0
  tfo=""
  if [ -r /proc/sys/net/ipv4/tcp_fastopen ]; then
    local _tfo_v; _tfo_v=$(cat /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null || echo 0)
    # kernel value: bit0 client, bit1 server — non-zero means TFO available
    if [ "${_tfo_v:-0}" != 0 ]; then tfo=" tfo"; fi
  fi
  if [ "${FINIXO_DISABLE_IPV6:-1}" != 1 ] && [ -s /proc/net/if_inet6 ] 2>/dev/null; then v6=1; fi
  local bind80="    bind *:80${tfo} backlog 4096"
  local bind443="    bind *:443 ssl crt ${HAP_PEM} alpn http/1.1${tfo} backlog 4096"
  if [ "$v6" = 1 ]; then
    bind80="${bind80}
    bind :::80${tfo} backlog 4096 v4v6"
    bind443="${bind443}
    bind :::443 ssl crt ${HAP_PEM} alpn http/1.1${tfo} backlog 4096 v4v6"
  fi

  [ -f "$HAP_CFG" ] && cp -a "$HAP_CFG" "${HAP_CFG}.finixo.bak" 2>/dev/null || true
  write_atomic_from_stdin "$HAP_CFG" 644 <<EOF
# Finixo Gate — HAProxy edge (generated — do not edit by hand)
global
    maxconn 65535
    tune.bufsize 32768
    tune.maxrewrite 8192
    tune.ssl.default-dh-param 2048
    hard-stop-after 5m
$HAP_USER_LINE
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    stats timeout 30s
    # Runtime API for live connection/device counts (localhost only)
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s

defaults
    mode http
    log global
    option dontlognull
    option http-keep-alive
    option redispatch
    retries 2
    timeout connect 10s
    timeout client  24h
    timeout server  24h
    timeout tunnel  24h
    timeout http-request 15s
    timeout http-keep-alive 10s
    timeout queue 10s

frontend fe_http
$bind80
    # Real client IP (never trust client-supplied XFF)
    http-request set-header X-Forwarded-Proto http
    http-request set-header X-Real-IP %[src]
    http-request set-header X-Forwarded-For %[src]
    http-request set-header CF-Connecting-IP %[src]
    acl acme path_beg /.well-known/acme-challenge/
    use_backend be_site if acme
    # Optional cleartext WS (same paths) for networks that strip TLS on 80
    acl p_vless path_beg -i ${WSP_VLESS}
    acl p_vmess path_beg -i ${WSP_VMESS}
    acl p_trojan path_beg -i ${WSP_TROJAN}
    acl p_ss path_beg -i ${WSP_SS}
    acl p_ssh path_beg -i ${WSP_SSH}
    use_backend be_vless if p_vless
    use_backend be_vmess if p_vmess
    use_backend be_trojan if p_trojan
    use_backend be_ss if p_ss
    use_backend be_ssh if p_ssh
    default_backend be_site

frontend fe_https
$bind443
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Proto http if !{ ssl_fc }
    http-request set-header X-Real-IP %[src]
    http-request set-header X-Forwarded-For %[src]
    http-request set-header CF-Connecting-IP %[src]
    acl p_vless path_beg -i ${WSP_VLESS}
    acl p_vmess path_beg -i ${WSP_VMESS}
    acl p_trojan path_beg -i ${WSP_TROJAN}
    acl p_ss path_beg -i ${WSP_SS}
    acl p_ssh path_beg -i ${WSP_SSH}
    use_backend be_vless if p_vless
    use_backend be_vmess if p_vmess
    use_backend be_trojan if p_trojan
    use_backend be_ss if p_ss
    use_backend be_ssh if p_ssh
    default_backend be_site

# Stick tables: unique client IP → concurrent WS tunnels (conn_cur)
# Used by: finixo online / devices  (HAProxy edge device counter)
backend st_vless
    stick-table type ip size 200k expire 30m store conn_cur,conn_cnt
backend st_vmess
    stick-table type ip size 200k expire 30m store conn_cur,conn_cnt
backend st_trojan
    stick-table type ip size 200k expire 30m store conn_cur,conn_cnt
backend st_ss
    stick-table type ip size 200k expire 30m store conn_cur,conn_cnt
backend st_ssh
    stick-table type ip size 100k expire 30m store conn_cur,conn_cnt

backend be_vless
    mode http
    option http-server-close
    timeout tunnel 24h
    # Track real client IP for accurate multi-device count (shared UUID OK)
    http-request track-sc0 src table st_vless
    server xray 127.0.0.1:${P_VLESS} maxconn 20000

backend be_vmess
    mode http
    option http-server-close
    timeout tunnel 24h
    http-request track-sc0 src table st_vmess
    server xray 127.0.0.1:${P_VMESS} maxconn 20000

backend be_trojan
    mode http
    option http-server-close
    timeout tunnel 24h
    http-request track-sc0 src table st_trojan
    server xray 127.0.0.1:${P_TROJAN} maxconn 20000

backend be_ss
    mode http
    option http-server-close
    timeout tunnel 24h
    http-request track-sc0 src table st_ss
    server xray 127.0.0.1:${P_SS} maxconn 20000

backend be_ssh
    mode http
    option http-server-close
    timeout tunnel 24h
    http-request track-sc0 src table st_ssh
    server bridge 127.0.0.1:${P_SSHWS} maxconn 10000

backend be_site
    mode http
    option http-server-close
    server nginx 127.0.0.1:18080 maxconn 5000
EOF

  # systemd hardening for HAProxy
  write_atomic_from_stdin "$HAP_SYSD" 644 <<'EOF'
[Unit]
StartLimitIntervalSec=0

[Service]
LimitNOFILE=1048576
Restart=always
RestartSec=2
OOMScoreAdjust=-200
EOF

  HAP_BIN=$(command -v haproxy || echo /usr/sbin/haproxy)
  if ! "$HAP_BIN" -c -f "$HAP_CFG" >/dev/null 2>&1; then
    err "HAProxy config test failed"
    "$HAP_BIN" -c -f "$HAP_CFG" || true
    if [ -f "${HAP_CFG}.finixo.bak" ]; then
      mv -f "${HAP_CFG}.finixo.bak" "$HAP_CFG"
      warn "Restored previous HAProxy config from backup"
    fi
    return 1
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable haproxy >/dev/null 2>&1 || true
  # Soft reload preferred (hard-stop-after 5m bounds old workers). Keep .bak until live.
  local hap_live=0
  if ! systemctl is-active --quiet haproxy 2>/dev/null; then
    if systemctl restart haproxy >/dev/null 2>&1; then hap_live=1; fi
  else
    if systemctl reload haproxy >/dev/null 2>&1; then
      hap_live=1
    else
      warn "HAProxy reload failed — trying restart"
      if systemctl restart haproxy >/dev/null 2>&1; then hap_live=1; fi
    fi
  fi
  if [ "$hap_live" != 1 ]; then
    err "HAProxy reload/restart failed"
    if [ -f "${HAP_CFG}.finixo.bak" ]; then
      mv -f "${HAP_CFG}.finixo.bak" "$HAP_CFG"
      warn "Restored previous HAProxy config from backup"
      systemctl restart haproxy >/dev/null 2>&1 || true
    fi
    return 1
  fi
  rm -f "${HAP_CFG}.finixo.bak" 2>/dev/null || true
  ok "HAProxy edge active (TLS + path route → Xray / SSH-WS / site)"
  return 0
}


write_nginx_full() {
  init_work_dir || return 1
  validate_ngx_limits || { err "Invalid NGX_LIMIT_* values."; return 1; }
  # Preserve nested force (FINIXO_SKIP_HAP=1 FINIXO_EDGE=nginx write_nginx_full)
  local _edge_keep="${FINIXO_EDGE:-}" _skip_keep="${FINIXO_SKIP_HAP:-0}"
  load_conf
  if [ "${_skip_keep}" = 1 ]; then
    FINIXO_SKIP_HAP=1
    FINIXO_EDGE="${_edge_keep:-nginx}"
  fi
  [ -f "$TLS_CRT" ] && [ -f "$TLS_KEY" ] || { err "The TLS certificate is missing."; return 1; }
  local snap rc v6_80="" v6_443="" listen_http="" listen_https=""
  # Edge mode: HAProxy owns public ports → Nginx only on 127.0.0.1:18080 (site + ACME)
  if [ "${FINIXO_EDGE:-haproxy}" = haproxy ]; then
    listen_http='    listen 127.0.0.1:18080 default_server so_keepalive=30s:15s:4 backlog=65535;'
    # Internal-only SSL (HAProxy owns public 443); keeps cert reload paths valid
    listen_https='    listen 127.0.0.1:18443 ssl default_server so_keepalive=30s:15s:4 backlog=1024;'
    v6_80=''; v6_443=''
  else
    listen_http='    listen 80 default_server reuseport so_keepalive=30s:15s:4 backlog=65535;'
    listen_https='    listen 443 ssl default_server reuseport so_keepalive=30s:15s:4 backlog=65535;'
    if ngx_v6; then v6_80='    listen [::]:80 default_server;'; v6_443='    listen [::]:443 ssl default_server;'; fi
  fi
  snap=$(mktemp -d "$WORK_DIR/ngxsnap.XXXXXX") || return 1
  ngx_snapshot "$snap"

  write_nginx_rate_zone || { ngx_rollback "$snap"; rm -rf "$snap"; return 1; }
  write_nginx_perf || true
  write_ws_logrotate || true
  write_nginx_stealth || true
  install_site_extras || true
  nginx_boost_system || true
  rm -f /etc/nginx/conf.d/finixo-rate.conf /etc/nginx/conf.d/99-finixo-acme.conf

  {
    echo "# Finixo WebSocket locations (high-speed 101 upgrade path)."
    ws_location "$WSP_VLESS"  "$P_VLESS"
    ws_location "$WSP_VMESS"  "$P_VMESS"
    ws_location "$WSP_TROJAN" "$P_TROJAN"
    ws_location "$WSP_SS"     "$P_SS"
    ws_location "$WSP_SSH"    "$P_SSHWS"
  } | write_atomic_from_stdin "$NGX_WS" 644
  rc=$?
  [ "$rc" -le 1 ] || { ngx_rollback "$snap"; rm -rf "$snap"; return 1; }

  write_atomic_from_stdin "$NGX_CONF" 644 <<EOF2
# Finixo Gate — hardened Nginx (max throughput + security)
server {
$listen_http
$v6_80
    server_name _;
    server_tokens off;
    access_log off;
    root $SITE_ROOT;
    index index.html;
    # Let's Encrypt webroot (certbot renew without stopping nginx)
    location ^~ /.well-known/acme-challenge/ {
        default_type text/plain;
        allow all;
    }
    error_page 400 403 404 405 408 414 =404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /404.html { internal; }
    location = /50x.html { internal; }
    location / { try_files \$uri \$uri/ =404; }
    include $NGX_WS;
}

server {
$listen_https
$v6_443
    server_name _;
    server_tokens off;
    access_log off;

    ssl_certificate     $TLS_CRT;
    ssl_certificate_key $TLS_KEY;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_ecdh_curve      X25519:prime256v1:secp384r1;
    ssl_session_cache   shared:FINIXO_SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_buffer_size     16k;
    resolver 1.1.1.1 8.8.8.8 9.9.9.9 valid=300s ipv6=off;
    resolver_timeout 3s;

    # Security headers
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    # High-performance keepalive for many concurrent WS clients
    keepalive_timeout 120s;
    keepalive_requests 10000;
    client_header_timeout 20s;
    client_body_timeout 20s;
    send_timeout 60s;
    reset_timedout_connection on;
    gzip off;

    root $SITE_ROOT;
    index index.html;
    error_page 400 403 404 405 408 414 =404 /404.html;
    error_page 500 502 503 504 /50x.html;
    location = /404.html { internal; }
    location = /50x.html { internal; }
    location / { try_files \$uri \$uri/ =404; }
    include $NGX_WS;
}
EOF2
  rc=$?
  [ "$rc" -le 1 ] || { ngx_rollback "$snap"; rm -rf "$snap"; return 1; }

  if ! nginx -t >/dev/null 2>&1; then
    nginx -t || true
    ngx_rollback "$snap"; rm -rf "$snap"; return 1
  fi
  if ! systemctl reload nginx >/dev/null 2>&1 && ! systemctl restart nginx >/dev/null 2>&1; then
    err "Nginx reload failed; restoring the previous configuration."
    ngx_rollback "$snap"
    nginx -t >/dev/null 2>&1 && { systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true; }
    rm -rf "$snap"; return 1
  fi
  rm -rf "$snap"
  if [ "${FINIXO_EDGE:-haproxy}" = haproxy ] && [ "${FINIXO_SKIP_HAP:-0}" != 1 ]; then
    # Nginx is now localhost-only; free public 80/443 before HAProxy binds
    if ! release_public_http_ports; then
      err "Cannot start HAProxy edge while public ports are busy"
      return 1
    fi
    if ! write_haproxy_full; then
      err "HAProxy edge failed — temporary Nginx public fallback (edge NOT permanently switched yet)"
      systemctl stop haproxy >/dev/null 2>&1 || true
      local edge_ok=0
      if FINIXO_SKIP_HAP=1 FINIXO_EDGE=nginx write_nginx_full; then
        if ss -tlnp 2>/dev/null | gq -qE ':(80|443)\b'; then
          FINIXO_EDGE=nginx
          if [ -f "$ENV_FILE" ]; then
            grep -v '^FINIXO_EDGE=' "$ENV_FILE" > "${ENV_FILE}.tmp" 2>/dev/null || true
            echo 'FINIXO_EDGE=nginx' >> "${ENV_FILE}.tmp"
            chmod 600 "${ENV_FILE}.tmp" 2>/dev/null || true
            mv -f "${ENV_FILE}.tmp" "$ENV_FILE" 2>/dev/null || true
            chmod 600 "$ENV_FILE" 2>/dev/null || true
          fi
          systemctl disable haproxy >/dev/null 2>&1 || true
          warn "Edge set to nginx after verified public bind. Restore with: FINIXO_EDGE=haproxy finixo repair"
          info "Tip: 3.2.5+ frees nginx public ports automatically before HAProxy binds."
          edge_ok=1
        else
          err "Fallback Nginx did not bind public 80/443 — FINIXO_EDGE stays haproxy; run: finixo repair"
        fi
      else
        err "Nginx public fallback failed — ports may be down; run: finixo repair"
      fi
      # Try to bring HAProxy back if fallback did not fully succeed
      if [ "$edge_ok" != 1 ]; then
        systemctl start haproxy >/dev/null 2>&1 || true
        return 1
      fi
    fi
  elif [ "${FINIXO_EDGE:-haproxy}" != haproxy ]; then
    systemctl disable --now haproxy >/dev/null 2>&1 || true
  fi
  return 0
}

install_site() {
  install -d -m 755 "$SITE_ROOT" || return 1
  install -d -m 755 "$SITE_ROOT/.well-known/acme-challenge" || true
  local n title body
  n=$((RANDOM % 4))
  case $n in
    0) title="Status"; body="<h1>Service Status</h1><p>All systems operational.</p>" ;;
    1) title="Docs"; body="<h1>API Documentation</h1><p>Public endpoints are documented internally.</p>" ;;
    2) title="App"; body="<h1>Application Portal</h1><p>Please sign in to continue.</p>" ;;
    *) title="Site"; body="<h1>Maintenance</h1><p>Scheduled maintenance is in progress.</p>" ;;
  esac
  cat > "$SITE_ROOT/index.html" <<EOF2
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:12vh auto;color:#222;padding:0 1.2rem;line-height:1.5}</style>
</head>
<body>${body}</body>
</html>
EOF2
  chmod 644 "$SITE_ROOT/index.html"
}

# Allow every real sshd port BEFORE enabling UFW; also open 80/443 in the raw
# iptables INPUT chain (Oracle Cloud images ship a REJECT rule there).

# Block tunnel-only SSH users from reaching private/link-local destinations (SSRF).
setup_nft_tunnel_guard() {
  if ! command -v nft >/dev/null 2>&1; then
    warn "nft not installed: tunnel users are NOT blocked from 127.0.0.1 (Xray API). Install nftables, then run: finixo repair"
    return 0
  fi
  local gid
  gid=$(getent group "${SSH_GROUP:-tunnel-only}" | cut -d: -f3)
  [ -n "$gid" ] || return 0
  nft list table inet finixo >/dev/null 2>&1 || nft add table inet finixo 2>/dev/null || return 0
  nft list chain inet finixo out >/dev/null 2>&1 || \
    nft 'add chain inet finixo out { type filter hook output priority 0; policy accept; }' 2>/dev/null || return 0
  # Idempotent: flush our chain then re-add rules
  nft flush chain inet finixo out 2>/dev/null || true
  nft add rule inet finixo out meta skgid "$gid" ip daddr 127.0.0.53 udp dport 53 accept 2>/dev/null || true
  nft add rule inet finixo out meta skgid "$gid" ip daddr 127.0.0.53 tcp dport 53 accept 2>/dev/null || true
  nft add rule inet finixo out meta skgid "$gid" ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } reject 2>/dev/null || true
  nft add rule inet finixo out meta skgid "$gid" ip6 daddr { ::1/128, fc00::/7, fe80::/10 } reject 2>/dev/null || true
  # Optional: reduce outbound spam complaints
  nft add rule inet finixo out meta skgid "$gid" tcp dport 25 reject 2>/dev/null || true
  mkdir -p /etc/nftables.d 2>/dev/null || true
  local guard_file=/etc/nftables.d/finixo-tunnel-guard.nft cand raw_ok=0
  cand=$(mktemp "${guard_file}.XXXXXX") || return 0
  cat > "$cand" <<NFT
table inet finixo
delete table inet finixo
table inet finixo {
  chain out {
    type filter hook output priority 0; policy accept;
    meta skgid $gid ip daddr 127.0.0.53 udp dport 53 accept
    meta skgid $gid ip daddr 127.0.0.53 tcp dport 53 accept
    meta skgid $gid ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } reject
    meta skgid $gid ip6 daddr { ::1/128, fc00::/7, fe80::/10 } reject
    meta skgid $gid tcp dport 25 reject
  }
}
NFT
  # Loopback traffic (Nginx -> Xray / bridge -> sshd) never needs connection tracking: skipping it
  # halves conntrack usage and CPU per tunnel. Added only when nft accepts the whole file.
  if [ "${FINIXO_NO_NOTRACK:-0}" != 1 ]; then
    cat >> "$cand" <<NFT
table inet finixo_raw
delete table inet finixo_raw
table inet finixo_raw {
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    iifname "lo" notrack
  }
  chain out {
    type filter hook output priority raw; policy accept;
    oifname "lo" notrack
  }
}
NFT
    if nft -c -f "$cand" >/dev/null 2>&1; then
      raw_ok=1
    else
      # strip the raw part again: the guard itself must always load
      sed -i '/^table inet finixo_raw$/,$d' "$cand"
    fi
  fi
  mv -f "$cand" "$guard_file"; chmod 644 "$guard_file"
  if [ "$raw_ok" = 1 ]; then
    nft -f "$guard_file" >/dev/null 2>&1 || true
  fi
  # Own oneshot unit: the rules come back after every reboot even when nftables.service is disabled.
  write_atomic_from_stdin /etc/systemd/system/finixo-nft-guard.service 644 <<UNIT
[Unit]
Description=Finixo tunnel-only guard (nftables)
After=network-pre.target nftables.service
Before=network.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$(command -v nft) -f /etc/nftables.d/finixo-tunnel-guard.nft
ExecStop=-$(command -v nft) delete table inet finixo
ExecStop=-$(command -v nft) delete table inet finixo_raw

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable finixo-nft-guard >/dev/null 2>&1 || true
  ok "nftables tunnel-only private-destination guard applied (gid=$gid)"
}

setup_firewall() {
  local p ports changed=0
  ports=$(ssh_ports_all)
  [ -n "$ports" ] || ports=22
  for p in $ports; do ufw allow "$p/tcp" >/dev/null 2>&1 || return 1; done
  ufw allow 80/tcp >/dev/null 2>&1 || return 1
  ufw allow 443/tcp >/dev/null 2>&1 || return 1
  # Default deny: only Finixo ports + SSH stay open. Other local services need explicit ufw allow.
  if [ "${FINIXO_UFW_SKIP_DENY:-0}" != 1 ]; then
    ufw default deny incoming >/dev/null 2>&1 || return 1
  fi
  ufw default allow outgoing >/dev/null 2>&1 || return 1
  ufw --force enable >/dev/null 2>&1 || return 1
  if command -v iptables >/dev/null 2>&1; then
    for p in 80 443; do
      if ! iptables -C INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1; then
        iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1 && changed=1
      fi
    done
    if [ "$changed" -eq 1 ] && command -v netfilter-persistent >/dev/null 2>&1; then
      netfilter-persistent save >/dev/null 2>&1 || true
    fi
  fi
  return 0
}

# ----------------------------------------------------------------------------
# Kernel / firewall tuning for long-lived tunnels (BBR, dead-peer cleanup, conntrack headroom)
# ----------------------------------------------------------------------------
# Conntrack ceiling scaled to RAM (an entry costs ~320 B and is only allocated when used).
conntrack_max_for_ram() {
  local t m
  t=$(sys_mem_total_mib); t=${t:-1024}
  m=$((t * 256))
  [ "$m" -ge 65536 ] || m=65536
  [ "$m" -le 524288 ] || m=524288
  echo "$m"
}

sysctl_profile() {
  local ctmax dis6=${FINIXO_DISABLE_IPV6:-1}
  ctmax=$(conntrack_max_for_ram)
  # When IPv6 is kept, do not write disable_ipv6=1
  cat <<SYS
# Finixo Gate — high-throughput + stability + harden (managed file: rewritten by install / repair / harden)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
# A peer that vanished without a FIN (phone switched network) is dropped after ~2-4 min instead of
# ~15 min: zombie tunnels end, the online counter stays honest, memory is freed.
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 131072 67108864
net.ipv4.tcp_wmem = 4096 131072 67108864
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
# Disable IPv6 on the host (Finixo default). Set FINIXO_DISABLE_IPV6=0 before harden/repair to keep IPv6.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
fs.file-max = 2097152
kernel.kptr_restrict = 2
kernel.sysrq = 0
# Keep Xray / Nginx memory resident (matters only when the VPS has swap).
vm.swappiness = 10
# Connection-tracking headroom (ignored when the module is absent).
-net.netfilter.nf_conntrack_max = $ctmax
-net.netfilter.nf_conntrack_tcp_timeout_established = 86400
-net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
-net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
-net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
SYS
}

# 0 = applied, 1 = skipped (container) — never fatal.
apply_perf_tuning() {
  if is_container; then
    warn "Container detected — skipping host sysctl/BBR (set on the host)"
    return 1
  fi
  install -d -m 755 /etc/sysctl.d /etc/modules-load.d 2>/dev/null || true
  # Load conntrack + BBR early at boot so the sysctls above also apply after a reboot.
  { modprobe -n nf_conntrack >/dev/null 2>&1 && echo nf_conntrack
    true; } | write_atomic_from_stdin /etc/modules-load.d/finixo.conf 644
  if modprobe -n tcp_bbr >/dev/null 2>&1; then echo tcp_bbr | write_atomic_from_stdin /etc/modules-load.d/bbr.conf 644; fi
  modprobe nf_conntrack >/dev/null 2>&1 || true
  modprobe tcp_bbr >/dev/null 2>&1 || true
  sysctl_profile | write_atomic_from_stdin /etc/sysctl.d/99-finixo-harden.conf 644
  if [ "${FINIXO_DISABLE_IPV6:-1}" != 1 ]; then
    # Keep IPv6: strip disable lines from the managed sysctl file
    sed -i -E '/net\.ipv6\.conf\.(all|default|lo)\.disable_ipv6/d' /etc/sysctl.d/99-finixo-harden.conf 2>/dev/null || true
    # Ensure IPv6 is not left disabled from a previous run
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1 || true
  fi
  sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-finixo-harden.conf >/dev/null 2>&1 || true
  if [ "${FINIXO_DISABLE_IPV6:-1}" = 1 ]; then
    ok "IPv6 disabled on host (sysctl disable_ipv6=1)"
  else
    info "IPv6 left enabled (FINIXO_DISABLE_IPV6=0)"
  fi
  return 0
}

# ----------------------------------------------------------------------------
# Harden — performance + security (safe defaults, reversible via package tools)
# ----------------------------------------------------------------------------
do_harden() {
  need_root
  load_conf 2>/dev/null || true
  # Nested steps must not inflate the outer install counter ([11/10] …)
  local _saved_n=${STEP_N:-0} _saved_t=${STEP_T:-10}
  STEP_N=0
  STEP_T=5

  step "Hardening: kernel network (BBR + buffers)"
  if ! is_container; then
    apply_perf_tuning
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | gq -q bbr; then ok "BBR enabled"
    else warn "BBR not active (kernel may lack it); fq/sysctl still applied where possible"; fi
  else
    warn "Container detected — skipping host sysctl/BBR (set on the host)"
  fi

  step "Hardening: file permissions"
  [ -f "$TLS_KEY" ] && chmod 600 "$TLS_KEY" 2>/dev/null || true
  [ -f "$TLS_CRT" ] && chmod 644 "$TLS_CRT" 2>/dev/null || true
  [ -f "$XRAY_CFG" ] && chmod 640 "$XRAY_CFG" 2>/dev/null || true
  [ -d "$XRAY_DIR" ] && chmod 750 "$XRAY_DIR" 2>/dev/null || true
  [ -f "$BRIDGE" ] && chmod 755 "$BRIDGE" 2>/dev/null || true
  [ -f "$HOLD" ] && chmod 755 "$HOLD" 2>/dev/null || true
  [ -f "$ENV_FILE" ] && chmod 600 "$ENV_FILE" 2>/dev/null || true
  ok "Sensitive paths permission-checked"

  step "Hardening: fail2ban (SSH)"
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y -qq fail2ban >/dev/null 2>&1 || true
  fi
  if command -v fail2ban-client >/dev/null 2>&1; then
    # No "backend = auto": Debian 12 logs sshd to journald only (no /var/log/auth.log), and the distro default
    # for [sshd] is the systemd backend, which needs python3-systemd.
    if command -v journalctl >/dev/null 2>&1 && ! python3 -c 'import systemd.journal' >/dev/null 2>&1; then
      env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y -qq python3-systemd >/dev/null 2>&1 || true
    fi
    local f2b_ports
    f2b_ports=$(ssh_ports_all 2>/dev/null | sort -un | paste -sd, - 2>/dev/null)
    [ -n "$f2b_ports" ] || f2b_ports=$(ssh_port 2>/dev/null || echo 22)
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/finixo-ssh.conf <<F2B
[sshd]
enabled  = true
port     = $f2b_ports
maxretry = 5
findtime = 10m
bantime  = 1h
ignoreip = 127.0.0.1/8 ::1
F2B
    systemctl enable --now fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban >/dev/null 2>&1 || true
    sleep 1
    if systemctl is-active --quiet fail2ban 2>/dev/null; then ok "fail2ban enabled for sshd (port $f2b_ports)"
    else warn "fail2ban is not running — see: journalctl -u fail2ban -n 20 --no-pager"; fi
  else
    warn "fail2ban could not be installed"
  fi

  step "Hardening: firewall refresh"
  setup_firewall && ok "UFW defaults applied (deny incoming, allow SSH/80/443)" || warn "UFW refresh incomplete"

  step "Hardening: time sync (required for VMess)"
  if ensure_time_sync; then ok "Clock synchronized"
  elif is_container; then warn "Container clock follows the host — keep the host NTP accurate"
  else warn "Could not confirm NTP; VMess may fail if clock drifts"; fi

  STEP_N=$_saved_n
  STEP_T=$_saved_t
  ok "Harden complete. Re-run: finixo test"
}

# ----------------------------------------------------------------------------
# Probes
# ----------------------------------------------------------------------------
# ws_probe ADDR PORT TLS(0|1) SNI HOST PATH [ssh]
# Prints: line1 = HTTP status line, line2 = SHA-256 of the served cert (TLS),
#         line3 = "banner" when an SSH banner followed the 101 (mode "ssh").
# The certificate is NOT verified (self-signed by design).
ws_probe() {
  python3 - "$@" <<'PY'
import hashlib, os, socket, ssl, sys, time
a = sys.argv[1:]
addr, port, tls, sni, host, path = a[:6]
ssh = len(a) > 6 and a[6] == "ssh"
try:
    T = max(0.5, float(os.environ.get("FINIXO_PROBE_T") or 6))   # watchdog uses 3 s
except ValueError:
    T = 6.0

def has_ssh_banner(buf: bytes) -> bool:
    # Banner may arrive fragmented across recv() calls.
    if b"SSH-2.0-" in buf:
        return True
    if b"\r\n\r\n" in buf and b"SSH-2.0-" in buf.split(b"\r\n\r\n", 1)[1]:
        return True
    return False

try:
    s = socket.create_connection((addr.strip("[]"), int(port)), T)
    fp = ""
    if tls == "1":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        s = ctx.wrap_socket(s, server_hostname=sni)
        fp = hashlib.sha256(s.getpeercert(True)).hexdigest()
    s.settimeout(min(1.0, T))
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
           "Sec-WebSocket-Version: 13\r\n\r\n").encode()
    if ssh:
        req += b"SSH-2.0-FinixoProbe_1.0\r\n"
    s.sendall(req)
    buf = b""
    deadline = time.monotonic() + T
    while len(buf) < 16384 and time.monotonic() < deadline:
        if not ssh and b"\r\n" in buf:
            break
        if ssh and has_ssh_banner(buf):
            break
        try:
            c = s.recv(4096)
        except socket.timeout:
            if not ssh and b"\r\n" in buf:
                break
            if ssh and has_ssh_banner(buf):
                break
            continue
        if not c:
            break
        buf += c
    try:
        s.close()
    except Exception:
        pass
    status = buf.split(b"\r\n", 1)[0].decode("latin1") if buf else ""
    print(status)
    print(fp)
    print("banner" if ssh and has_ssh_banner(buf) else "")
except Exception as e:
    print("ERR " + str(e))
    print("")
    print("")
PY
}

find_free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# Test client: Xray -> Nginx :80 on this machine -> Xray server -> Internet.
# Plain WebSocket on port 80, so it tests the real data path without any
# dependency on certificates, DNS or hairpin NAT.
build_client_config() {
  local proto=$1 socks_port=$2 out=$3 id secret method outbound
  load_conf
  local ws
  ws="\"streamSettings\":{\"network\":\"ws\",\"security\":\"none\",\"wsSettings\":{\"path\":\"@PATH@\",\"headers\":{\"Host\":\"$CLIENT_HOST\"}}}"
  case "$proto" in
    vless)
      id=$(jq -r '.inbounds[]|select(.tag=="vless-ws").settings.clients[0].id' "$XRAY_CFG") || return 1
      outbound="{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"127.0.0.1\",\"port\":${E2E_PORT:-80},\"users\":[{\"id\":\"$id\",\"encryption\":\"none\",\"level\":0}]}]},${ws//@PATH@/$WSP_VLESS}}" ;;
    vmess)
      id=$(jq -r '.inbounds[]|select(.tag=="vmess-ws").settings.clients[0].id' "$XRAY_CFG") || return 1
      outbound="{\"protocol\":\"vmess\",\"settings\":{\"vnext\":[{\"address\":\"127.0.0.1\",\"port\":${E2E_PORT:-80},\"users\":[{\"id\":\"$id\",\"alterId\":0,\"security\":\"auto\",\"level\":0}]}]},${ws//@PATH@/$WSP_VMESS}}" ;;
    trojan)
      secret=$(jq -r '.inbounds[]|select(.tag=="trojan-ws").settings.clients[0].password' "$XRAY_CFG") || return 1
      outbound="{\"protocol\":\"trojan\",\"settings\":{\"servers\":[{\"address\":\"127.0.0.1\",\"port\":${E2E_PORT:-80},\"password\":\"$secret\",\"level\":0}]},${ws//@PATH@/$WSP_TROJAN}}" ;;
    ss)
      secret=$(ss_password) || return 1
      method=$(ss_method) || return 1
      outbound="{\"protocol\":\"shadowsocks\",\"settings\":{\"servers\":[{\"address\":\"127.0.0.1\",\"port\":${E2E_PORT:-80},\"method\":\"$method\",\"password\":\"$secret\",\"level\":0}]},${ws//@PATH@/$WSP_SS}}" ;;
    *) return 1 ;;
  esac
  printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":%s,"protocol":"socks","settings":{"auth":"noauth","udp":false}}],"outbounds":[%s]}\n' \
    "$socks_port" "$outbound" > "$out"
  chmod 600 "$out"
  validate_xray_config_file "$out"
}

# Where the local test client connects. Preferred: Nginx on plain :80 (no certificate/DNS dependency). Some servers redirect :80
# to HTTPS (HTTP 301, e.g. a leftover server block for the domain) — then a client can never upgrade there, so the test goes
# straight to the Xray inbound instead (real data through the real credentials; the TLS front is covered by the :443 101 checks).
E2E_PORT=80; E2E_VIA="Nginx :80"
e2e_entry() {   # proto
  local pth port; local -a R3=()
  case $1 in vless) pth=$WSP_VLESS; port=$P_VLESS ;; vmess) pth=$WSP_VMESS; port=$P_VMESS ;; trojan) pth=$WSP_TROJAN; port=$P_TROJAN ;; ss) pth=$WSP_SS; port=$P_SS ;; *) return 0 ;; esac
  E2E_PORT=80; E2E_VIA="Nginx :80"
  mapfile -t R3 < <(FINIXO_PROBE_T=4 ws_probe 127.0.0.1 80 0 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$pth" 2>/dev/null)
  if [[ ${R3[0]:-} != *" 101"* ]]; then
    E2E_PORT=$port; E2E_VIA="edge :80 answered '${R3[0]:-nothing}' (HAProxy or Nginx)"
  fi
}
# One request through the local test client. Prints the HTTP code; "000" = no answer at all.
e2e_fetch() {   # socks-port url max-seconds
  local c
  c=$(curl -sS -o /dev/null -w '%{http_code}' --proxy "socks5h://127.0.0.1:$1" --connect-timeout 5 --max-time "${3:-15}" "$2" 2>/dev/null || true)
  [[ $c =~ ^[0-9]{3}$ ]] || c=000
  printf '%s' "$c"
}
# Success = a real answer: 2xx / 3xx (204 is the generate_204 contract). 000, 1xx, 4xx and 5xx are NOT success.
e2e_code_ok() { [[ ${1:-} =~ ^[23][0-9]{2}$ ]]; }

# Say WHAT failed, without blaming the protocol when only the exit side is broken:
#   upgrade fails (not 101)          -> Nginx route / Xray inbound / path
#   101 ok, server cannot fetch URL  -> this server's own exit (DNS, outbound firewall, blocked target)
#   101 ok, server can, tunnel can't -> data path / credentials
e2e_diagnose() {   # proto url code
  local proto=$1 url=$2 code=${3:-000} pth st direct
  local -a R3
  case $proto in vless) pth=$WSP_VLESS ;; vmess) pth=$WSP_VMESS ;; trojan) pth=$WSP_TROJAN ;; ss) pth=$WSP_SS ;; *) return 0 ;; esac
  mapfile -t R3 < <(ws_probe 127.0.0.1 "${E2E_PORT:-80}" 0 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$pth" 2>/dev/null)
  st=${R3[0]:-no answer}
  if [[ $st != *101* ]]; then
    err "$proto: the WebSocket upgrade itself failed ($st) — check the Nginx route, the Xray inbound and the path"
    return 0
  fi
  if [ "$code" != 000 ]; then
    warn "$proto: upgrade OK (101) and the tunnel carried the request, but the test target answered HTTP $code — data flows; try FINIXO_TEST_URL=<another https URL>"
    return 0
  fi
  direct=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 "$url" 2>/dev/null || true)
  if ! e2e_code_ok "$direct"; then
    warn "$proto: upgrade OK (101) but THIS SERVER cannot fetch $url either (direct HTTP ${direct:-000}) — DNS, outbound firewall or a blocked target; this is not a protocol fault"
    info "Check from the server:  curl -sS -m 8 -o /dev/null -w '%{http_code}\n' $url   (and: getent hosts www.gstatic.com)"
    [ -d "${WORK_DIR:-/nonexistent}/e2e" ] && : > "$WORK_DIR/e2e/egress.dead"
  else
    err "$proto: upgrade OK (101) and the server reaches $url directly (HTTP $direct), but nothing came back through the tunnel — check the user's key and: journalctl -u xray -n 40 --no-pager"
  fi
  return 0
}

protocol_e2e_probe() {
  local proto=$1 url=${FINIXO_TEST_URL:-https://www.gstatic.com/generate_204} sp cfg log code dir tag
  local alt=https://cp.cloudflare.com/generate_204 used c2 note="" t1=15 t2=20 dead=0
  init_work_dir || return 1
  # Skip E2E when inbound has zero clients (by design after zero-default install)
  case "$proto" in
    vless) tag=vless-ws ;;
    vmess) tag=vmess-ws ;;
    trojan) tag=trojan-ws ;;
    ss) tag=ss-ws ;;
    *) tag="" ;;
  esac
  if [ "$proto" != ss ] && [ -n "$tag" ]; then
    local n
    n=$(jq --arg t "$tag" '[.inbounds[]?|select(.tag==$t).settings.clients[]?]|length' "$XRAY_CFG" 2>/dev/null || echo 0)
    if [ "${n:-0}" -eq 0 ]; then
      warn "$proto data path: skipped (no users yet — add from menu)"
      return 2
    fi
  fi
  dir="$WORK_DIR/e2e"; install -d -m 700 "$dir" || return 1
  # The server's own exit was found dead a moment ago: keep the remaining probes short instead of waiting again.
  if [ -f "$dir/egress.dead" ] && [ $(( $(date +%s) - $(stat -c %Y "$dir/egress.dead" 2>/dev/null || echo 0) )) -lt 180 ]; then dead=1; t1=8; t2=8; fi
  sp=$(find_free_port) || return 1
  cfg=$(mktemp --suffix=.json "$dir/$proto.XXXXXX") || return 1
  log="$dir/$proto.log"
  e2e_entry "$proto"
  if ! build_client_config "$proto" "$sp" "$cfg"; then err "$proto: the test client configuration is invalid"; rm -f "$cfg"; return 1; fi
  "$XRAY_BIN" run -format json -config "$cfg" >"$log" 2>&1 &
  E2E_PID=$!
  if ! wait_port "$sp" 20; then
    err "$proto: the local test client did not start"
    kill "$E2E_PID" 2>/dev/null || true; wait "$E2E_PID" 2>/dev/null || true; E2E_PID=""
    rm -f "$cfg"; return 1
  fi
  used=$url
  code=$(e2e_fetch "$sp" "$url" "$t1")
  # one patient retry: the first DNS lookup on a fresh connection can be slow
  if [ "$code" = 000 ] && [ "$dead" = 0 ]; then code=$(e2e_fetch "$sp" "$url" "$t2"); fi
  if ! e2e_code_ok "$code" && [ -z "${FINIXO_TEST_URL:-}" ] && [ "$dead" = 0 ]; then
    c2=$(e2e_fetch "$sp" "$alt" "$t1")
    if e2e_code_ok "$c2"; then
      warn "$proto: $url did not answer through the tunnel (HTTP $code) but $alt did (HTTP $c2) — the tunnel works; the first target is blocked or slow from this server"
      code=$c2; used=$alt
    fi
  fi
  kill "$E2E_PID" 2>/dev/null || true; wait "$E2E_PID" 2>/dev/null || true; E2E_PID=""
  rm -f "$cfg"
  if e2e_code_ok "$code"; then
    case $used in *generate_204) [ "$code" = 204 ] || note=" (expected 204 — a captive portal or proxy may be answering in the middle)" ;; esac
    ok "$proto data path (client -> ${E2E_VIA} -> Internet): HTTP $code$note"
    rm -f "$log" "$dir/egress.dead"; return 0
  fi
  err "$proto data path failed (HTTP ${code:-000}; test URL $url)"
  e2e_diagnose "$proto" "$url" "$code"
  tail -n 8 "$log" 2>/dev/null || true
  rm -f "$log"
  return 1
}

# ----------------------------------------------------------------------------
# Links
# ----------------------------------------------------------------------------
mklink() {
  local tag=$1 n=$2 s=$3 force_sec=${4:-} enc json ui frag tlsq pc="" vtls="" vsni="" valpn="" method plugin_str
  local use_remote="$REMOTE_PROXY" use_host="$REMOTE_PROXY_HOST" use_port="$REMOTE_PROXY_PORT"
  load_conf
  validate_client_profile_syntax || return 1
  # Re-parse after load_conf
  use_remote="$REMOTE_PROXY"; use_host="$REMOTE_PROXY_HOST"; use_port="$REMOTE_PROXY_PORT"
  frag=$(url_encode "$SERVER_ADDR-$n")
  if [ "$force_sec" = none ] || [ "$tag" = "vless-ws-notls" ]; then
    tlsq="security=none"
    vtls=""; vsni=""; valpn=""
    # Non-TLS typically uses 80 (or whatever non-TLS port user set)
    case "$use_port" in
      443|8443|2053|2083|2087|2096) use_port=80 ;;
    esac
    if [[ "$use_host" == *:* ]]; then use_remote="[$use_host]:$use_port"; else use_remote="$use_host:$use_port"; fi
    tag=vless-ws
  elif [ "$force_sec" = tls ]; then
    tlsq="security=tls&sni=$(url_encode "$CLIENT_SNI")&fp=chrome&alpn=http%2F1.1"
    if use_pin; then pc=$(cert_sha256); [ -n "$pc" ] && tlsq="$tlsq&pcs=$pc"; fi
    vtls=tls; vsni=$CLIENT_SNI; valpn="http/1.1"
  elif client_tls; then
    tlsq="security=tls&sni=$(url_encode "$CLIENT_SNI")&fp=chrome&alpn=http%2F1.1"
    if use_pin; then pc=$(cert_sha256); [ -n "$pc" ] && tlsq="$tlsq&pcs=$pc"; fi
    vtls=tls; vsni=$CLIENT_SNI; valpn="http/1.1"
  else
    tlsq="security=none"
  fi
  case "$tag" in
    vless-ws)
      enc=$(url_encode "$WSP_VLESS")
      echo "vless://$s@$use_remote?encryption=none&$tlsq&type=ws&host=$(url_encode "$CLIENT_HOST")&path=$enc#$frag-VLESS"
      ;;
    vmess-ws)
      json=$(jq -nc --arg ps "$SERVER_ADDR-$n-VMess" --arg add "$REMOTE_PROXY_HOST" --arg port "$REMOTE_PROXY_PORT" \
        --arg id "$s" --arg path "$WSP_VMESS" --arg host "$CLIENT_HOST" --arg sni "$vsni" --arg tls "$vtls" \
        --arg alpn "$valpn" --arg pcs "$pc" \
        '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:$tls,sni:$sni,alpn:$alpn,fp:"chrome"} + (if $pcs != "" then {pcs:$pcs} else {} end)')
      echo "vmess://$(b64_oneline "$json")"
      ;;
    trojan-ws)
      enc=$(url_encode "$WSP_TROJAN")
      # allowInsecure ONLY for a self-signed cert without pin; never for CA certs (Let's Encrypt) or plain WS.
      local ai=""
      if client_tls && ! use_pin && cert_is_selfsigned; then ai="&allowInsecure=1"; fi
      echo "trojan://$s@$REMOTE_PROXY?$tlsq&type=ws&host=$(url_encode "$CLIENT_HOST")&path=$enc${ai}#$frag-Trojan"
      ;;
    ss-ws|ss-plugin)
      method=$(ss_method) || return 1
      [ -n "$method" ] || return 1
      ui=$(ss_userinfo "$method" "$s") || return 1
      if [ "$tag" = ss-ws ]; then
        enc=$(url_encode "$WSP_SS")
        echo "ss://$ui@$REMOTE_PROXY?type=ws&$tlsq&host=$(url_encode "$CLIENT_HOST")&path=$enc#$frag-SS"
      else
        plugin_str="v2ray-plugin;mode=websocket;host=$CLIENT_HOST;path=$WSP_SS;mux=0"
        client_tls && plugin_str="v2ray-plugin;mode=websocket;host=$CLIENT_HOST;path=$WSP_SS;tls;mux=0"
        echo "ss://$ui@$REMOTE_PROXY/?plugin=$(url_encode "$plugin_str")#$frag-SS-plugin"
      fi
      ;;
  esac
}

validate_generated_links() {
  load_conf
  validate_client_profile_syntax || return 1
  local v_id vm_id tr_pass ss_pass l1 l2 l3 l4 pin=0 tls=0
  v_id=$(jq -r '.inbounds[]|select(.tag=="vless-ws").settings.clients[0].id // empty' "$XRAY_CFG" 2>/dev/null)
  vm_id=$(jq -r '.inbounds[]|select(.tag=="vmess-ws").settings.clients[0].id // empty' "$XRAY_CFG" 2>/dev/null)
  tr_pass=$(jq -r '.inbounds[]|select(.tag=="trojan-ws").settings.clients[0].password // empty' "$XRAY_CFG" 2>/dev/null)
  ss_pass=$(ss_password) || return 1
  # No users yet: profile/SS still OK — skip link shape checks for empty protocols
  if [ -z "$v_id" ] && [ -z "$vm_id" ] && [ -z "$tr_pass" ]; then
    [ -n "$ss_pass" ] || return 1
    return 0
  fi
  [ -n "$v_id" ] || v_id=$(new_uuid)
  [ -n "$vm_id" ] || vm_id=$(new_uuid)
  [ -n "$tr_pass" ] || tr_pass=$(rand_hex 16)
  l1=$(mklink vless-ws default "$v_id") || return 1
  l2=$(mklink vmess-ws default "$vm_id") || return 1
  l3=$(mklink trojan-ws default "$tr_pass") || return 1
  l4=$(mklink ss-ws default "$ss_pass") || return 1
  use_pin && pin=1
  client_tls && tls=1
  python3 - "$REMOTE_PROXY" "$CLIENT_SNI" "$CLIENT_HOST" "$WSP_VLESS" "$WSP_VMESS" "$WSP_TROJAN" "$WSP_SS" \
    "$pin" "$tls" "$l1" "$l2" "$l3" "$l4" <<'PY'
import base64, json, sys
from urllib.parse import urlparse, parse_qs, unquote
remote, sni, host, p1, p2, p3, p4, pin, tls, *links = sys.argv[1:]
def chk(link, scheme, path):
    p = urlparse(link); q = parse_qs(p.query)
    assert p.scheme == scheme, scheme
    assert p.netloc.rsplit("@", 1)[1] == remote, "remote"
    assert q["type"] == ["ws"] and q["host"] == [host] and unquote(q["path"][0]) == path
    if tls == "1":
        assert q["security"] == ["tls"] and q["sni"] == [sni]
        assert (("pcs" in q) == (pin == "1"))
    else:
        assert q["security"] == ["none"]
chk(links[0], "vless", p1); chk(links[2], "trojan", p3); chk(links[3], "ss", p4)
vm = links[1][8:]; vm += "=" * ((4 - len(vm) % 4) % 4)
o = json.loads(base64.b64decode(vm).decode())
assert o["host"] == host and o["path"] == p2 and o["net"] == "ws"
print("ok")
PY
}

clients_of() {
  jq -r --arg t "$1" '.inbounds[]|select(.tag==$t).settings.clients[]?|"\(.email // "default")\t\(.id // .password)"' "$XRAY_CFG" 2>/dev/null
}

list_clients() {
  local tag=$1 n s i=0 exp left ot
  refresh_online_set
  while IFS=$'\t' read -r n s; do
    [ -n "$n" ] || continue
    i=$((i+1))
    ot=$(online_tag "$n")
    exp=$(awk -F'|' -v t="$tag" -v e="$n" '$1==t && $2==e {print $3; exit}' "$EXPIRY_DB" 2>/dev/null)
    if [ -n "$exp" ]; then
      left=$(expiry_left_text "$exp")
      if [ "$left" = "EXPIRED" ]; then
        printf '  %s%d) %s %s[EXPIRED]%s%s\n' "$W" "$i" "$n" "$R" "$N" "$ot"
      elif [ "$left" = "INVALID" ]; then
        printf '  %s%d) %s %s[expiry record unreadable — use Extend time to reset it]%s%s\n' "$W" "$i" "$n" "$Y" "$N" "$ot"
      else
        printf '  %s%d) %s %s(%s left)%s%s\n' "$W" "$i" "$n" "$D" "$left" "$N" "$ot"
      fi
    else
      printf '  %s%d) %s%s%s\n' "$W" "$i" "$n" "$N" "$ot"
    fi
    printf '     %s%s%s\n' "$C" "$(mklink "$tag" "$n" "$s")" "$N"
  done < <(clients_of "$tag")
  [ "$i" -gt 0 ] || warn "No users."
}

add_client() {
  local tag=$1 name secret days exp proto hot=0
  read -r -p "  User name (letters/digits/_-, max 32): " name
  [[ $name =~ ^[A-Za-z0-9_-]{1,32}$ ]] || { err "Invalid name."; return 1; }
  # One name = one Xray counter: a name already used on another protocol (or stored as disabled)
  # would make the online counter ambiguous, so it is refused.
  if xray_all_emails | gq -Fx -- "$name" || { [ -s "$DISABLED_DB" ] && awk -F'|' -v e="$name" '$2==e{f=1} END{exit !f}' "$DISABLED_DB"; }; then
    err "The name '$name' is already used (another protocol or disabled). Use a unique name per user."; return 1
  fi
  if jq -e --arg t "$tag" --arg n "$name" '.inbounds[]|select(.tag==$t).settings.clients[]|select(.email==$n)' "$XRAY_CFG" >/dev/null 2>&1; then
    err "User already exists."; return 1
  fi
  echo -e "  ${D}Duration examples: 30  |  7d  |  12h  |  1d6h  |  90m  |  2d12h30m${N}"
  read -r -p "  Valid for [30d]: " dur; dur=${dur:-30}
  if ! parse_duration "$dur"; then
    err "Invalid duration. Use e.g. 7d, 12h, 1d6h, 90m (min 1 minute)."; return 1
  fi
  exp=$(date -d "+${DUR_SECS} seconds" +%Y-%m-%dT%H:%M:%S) || { err "date failed"; return 1; }

  case "$tag" in
    trojan-ws) proto=trojan; secret=$(rand_hex 16) ;;
    vmess-ws)  proto=vmess;  secret=$(new_uuid) ;;
    *)         proto=vless;  secret=$(new_uuid) ;;
  esac

  # 1) Persist to disk first (survives future restarts)
  if [ "$tag" = trojan-ws ]; then
    cfg_apply_disk --arg t "$tag" --arg n "$name" --arg s "$secret" \
      '(.inbounds[]|select(.tag==$t).settings.clients) += [{password:$s,email:$n,level:0}]' || return 1
  else
    cfg_apply_disk --arg t "$tag" --arg n "$name" --arg s "$secret" \
      '(.inbounds[]|select(.tag==$t).settings.clients) += [{id:$s,email:$n,level:0}]' || return 1
  fi

  # 2) Hot-add via API (no restart → existing sessions stay up)
  if xray_api_add_user "$tag" "$name" "$secret" "$proto"; then
    hot=1
    ok "User added live (no restart, valid ${DUR_HUMAN}, expires $exp):"
  else
    # API unavailable → fall back to restart (warn user)
    info "Applying the change with a quick Xray restart (connections reconnect within seconds)..."
    if systemctl restart xray >/dev/null 2>&1 && wait_active xray 15; then
      ok "User added after restart (valid ${DUR_HUMAN}, expires $exp):"
    else
      err "Xray restart failed after adding user (config on disk — run: finixo repair)."
      install -d -m 755 "$CONF_DIR" 2>/dev/null || true
      touch "$EXPIRY_DB" 2>/dev/null || true
      chmod 600 "$EXPIRY_DB" 2>/dev/null || true
      local _edb; _edb=$(mktemp "$CONF_DIR/.expiry.XXXXXX") || _edb="${EXPIRY_DB}.$$.$RANDOM"
      grep -v "^${tag}|${name}|" "$EXPIRY_DB" > "$_edb" 2>/dev/null || true
      echo "${tag}|${name}|${exp}" >> "$_edb"
      mv -f "$_edb" "$EXPIRY_DB"
      return 1
    fi
  fi

  # Record expiry
  install -d -m 755 "$CONF_DIR" 2>/dev/null || true
  touch "$EXPIRY_DB" 2>/dev/null || true
  chmod 600 "$EXPIRY_DB" 2>/dev/null || true
  local _edb; _edb=$(mktemp "$CONF_DIR/.expiry.XXXXXX" 2>/dev/null) || _edb="${EXPIRY_DB}.$$.$RANDOM"
  grep -v "^${tag}|${name}|" "$EXPIRY_DB" > "$_edb" 2>/dev/null || true
  echo "${tag}|${name}|${exp}" >> "$_edb"
  mv -f "$_edb" "$EXPIRY_DB"
  printf '  %s%s%s\n' "$C" "$(mklink "$tag" "$name" "$secret")" "$N"
}

del_client() {
  local tag=$1 idx cnt name
  cnt=$(jq --arg t "$tag" '[.inbounds[]|select(.tag==$t).settings.clients[]]|length' "$XRAY_CFG" 2>/dev/null) || return 1
  list_clients "$tag"
  [ "$cnt" -ge 1 ] || { warn "No users."; return 0; }
  read -r -p "  Number to delete: " idx
  [[ $idx =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "$cnt" ] || { err "Invalid number."; return 1; }
  name=$(clients_of "$tag" | sed -n "${idx}p" | cut -f1)
  [ -n "$name" ] || { err "Invalid."; return 1; }
  read -r -p "  Delete '$name' permanently? [y/N] " _ans
  [[ ${_ans,,} == y || ${_ans,,} == yes ]] || { warn "Cancelled."; return 0; }

  # 1) Persist removal to disk
  if ! cfg_apply_disk --arg t "$tag" --arg n "$name" \
      '(.inbounds[]|select(.tag==$t).settings.clients) |= map(select(.email!=$n))'; then
    err "Could not update configuration."; return 1
  fi

  # 2) Remove from running core, then short restart so this user's sessions end.
  xray_api_rm_user "$tag" "$name" 2>/dev/null || true
  if [ -f "$EXPIRY_DB" ]; then
    grep -v "^${tag}|${name}|" "$EXPIRY_DB" > "${EXPIRY_DB}.tmp" 2>/dev/null || true
    mv -f "${EXPIRY_DB}.tmp" "$EXPIRY_DB" 2>/dev/null || true
  fi
  if [ -f "$DISABLED_DB" ]; then
    grep -v "^${tag}|${name}|" "$DISABLED_DB" > "${DISABLED_DB}.tmp" 2>/dev/null || true
    mv -f "${DISABLED_DB}.tmp" "$DISABLED_DB" 2>/dev/null || true
  fi
  info "Applying with a short Xray restart (other users reconnect in ~1–3 s)..."
  if systemctl restart xray >/dev/null 2>&1 && wait_active xray 15; then
    ok "Deleted $name (sessions closed)."
  else
    err "Xray restart failed after deleting user (already removed from config — run: finixo repair)."
    return 1
  fi
}


# ═══════════════════════════════════════════════════════════════════════════
# CONNECTION / SESSION CONTROL
# Disable = remove from live Xray (sessions die) but keep secrets for re-enable
# Enable  = restore live without full restart (API hot-add)
# Delete  = permanent wipe (config + API + expiry + disabled store)
# ═══════════════════════════════════════════════════════════════════════════

# A freshly generated Xray config has no users: records of the previous install must not survive,
# otherwise Enable could bring an old user (with an old secret) back to life.
reset_client_dbs() {
  install -d -m 755 "$CONF_DIR" 2>/dev/null || true
  : > "$EXPIRY_DB" 2>/dev/null || true
  : > "$DISABLED_DB" 2>/dev/null || true
  rm -f "$DEV_DB" 2>/dev/null || true
  chmod 600 "$EXPIRY_DB" "$DISABLED_DB" 2>/dev/null || true
}
ensure_client_dbs() {
  install -d -m 755 "$CONF_DIR" 2>/dev/null || true
  touch "$EXPIRY_DB" "$DISABLED_DB" 2>/dev/null || true
  chmod 600 "$EXPIRY_DB" "$DISABLED_DB" 2>/dev/null || true
}

# Extract secret for a live user (id or password)
client_secret_of() {
  local tag=$1 name=$2
  jq -r --arg t "$tag" --arg n "$name" '
    .inbounds[]|select(.tag==$t).settings.clients[]?
    | select(.email==$n)
    | (.id // .password // empty)
  ' "$XRAY_CFG" 2>/dev/null
}

client_proto_of() {
  case "$1" in
    trojan-ws) echo trojan ;;
    vmess-ws)  echo vmess ;;
    ss-ws)     echo ss ;;
    *)         echo vless ;;
  esac
}

# List ALL users across protocols with status
list_all_connections() {
  ensure_client_dbs
  local tag n s i=0 exp left st sess c k
  refresh_online_set
  print_online_summary
  echo
  echo -e "  ${W}━━ LIVE (can connect) ━━${N}"
  for tag in vless-ws vmess-ws trojan-ws; do
    while IFS=$'\t' read -r n s; do
      [ -n "$n" ] || continue
      i=$((i+1))
      exp=$(awk -F'|' -v t="$tag" -v e="$n" '$1==t && $2==e {print $3; exit}' "$EXPIRY_DB" 2>/dev/null)
      st="ACTIVE"
      if [ -n "$exp" ]; then
        left=$(expiry_left_text "$exp" 2>/dev/null || echo "?")
        if [ "$left" = "EXPIRED" ]; then st="EXPIRED"
        elif [ "$left" = "INVALID" ]; then st="ACTIVE · expiry record unreadable"
        else st="ACTIVE · ${left} left"; fi
      fi
      printf '  %s%2d)%s %-10s %-20s %s[%s]%s%s\n' "$W" "$i" "$N" "${tag%-ws}" "$n" "$G" "$st" "$N" "$(online_tag "$n")"
    done < <(clients_of "$tag")
  done
  [ "$i" -gt 0 ] || echo -e "  ${D}(none)${N}"

  echo
  echo -e "  ${W}━━ DISABLED (cannot connect — re-enable anytime) ━━${N}"
  local j=0
  if [ -s "$DISABLED_DB" ]; then
    while IFS='|' read -r tag n secret proto when; do
      [ -n "$n" ] || continue
      j=$((j+1))
      printf '  %s%2d)%s %-10s %-20s %s[DISABLED]%s  %s%s%s\n' \
        "$W" "$j" "$N" "${tag%-ws}" "$n" "$Y" "$N" "$D" "${when:-?}" "$N"
    done < "$DISABLED_DB"
  fi
  [ "$j" -gt 0 ] || echo -e "  ${D}(none)${N}"

  echo
  echo -e "  ${W}━━ SSH-WS users ━━${N}"
  sess=$(online_ssh_sessions)
  c=0
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    c=$((c+1))
    k=$(awk -v u="$n" '$1==u {print $2}' <<< "$sess")
    if ssh_user_locked "$n"; then
      printf '  %s%2d)%s %-10s %-20s %s⊘ DISABLED%s\n' "$W" "$c" "$N" ssh "$n" "$Y" "$N"
    elif [ -n "$k" ]; then
      printf '  %s%2d)%s %-10s %-20s %s● ONLINE%s %s(%s connection%s)%s\n' "$W" "$c" "$N" ssh "$n" "$G" "$N" "$D" "$k" "$([ "$k" -gt 1 ] && echo s)" "$N"
    else
      printf '  %s%2d)%s %-10s %-20s %s○ offline%s\n' "$W" "$c" "$N" ssh "$n" "$D" "$N"
    fi
  done < <(ssh_users)
  [ "$c" -gt 0 ] || echo -e "  ${D}(none)${N}"
}

# Disable: kill live access, keep secrets for later enable
disable_client() {
  local tag=$1 name=$2 secret proto
  ensure_client_dbs
  [ -n "$tag" ] && [ -n "$name" ] || { err "tag/name required"; return 1; }

  secret=$(client_secret_of "$tag" "$name")
  if [ -z "$secret" ]; then
    err "User '$name' not found in live config ($tag)."; return 1
  fi
  proto=$(client_proto_of "$tag")

  # Persist disable store FIRST (so we never lose the secret)
  # remove old line for same user if any
  if [ -f "$DISABLED_DB" ]; then
    grep -v "^${tag}|${name}|" "$DISABLED_DB" > "${DISABLED_DB}.tmp" 2>/dev/null || true
    mv -f "${DISABLED_DB}.tmp" "$DISABLED_DB" 2>/dev/null || true
  fi
  printf '%s|%s|%s|%s|%s\n' "$tag" "$name" "$secret" "$proto" "$(date -Iseconds)" >> "$DISABLED_DB"
  chmod 600 "$DISABLED_DB"

  # Remove from disk config
  if ! cfg_apply_disk --arg t "$tag" --arg n "$name" \
      '(.inbounds[]|select(.tag==$t).settings.clients) |= map(select(.email!=$n))'; then
    err "Could not update config to disable user."; return 1
  fi

  # Remove from running core (blocks new conns). Then restart once so existing
  # sessions for this user really die. Other users reconnect within ~1–3 s.
  xray_api_rm_user "$tag" "$name" 2>/dev/null || true
  if [ "${CC_BATCH:-0}" = 1 ]; then
    CC_RESTART_PENDING=1
    ok "DISABLED '$name' on $tag — access blocked; its open sessions end at the single Xray restart after this batch."
    return 0
  fi
  info "Dropping live sessions with a short Xray restart (every client reconnects within seconds)..."
  if systemctl restart xray >/dev/null 2>&1 && wait_active xray 15; then
    ok "DISABLED '$name' on $tag — access blocked, sessions closed."
  else
    err "Xray restart failed after disable."; return 1
  fi
  info "Re-enable anytime from Connection Control."
}

# Enable: restore from disabled store
enable_client() {
  local tag=$1 name=$2 secret proto line
  ensure_client_dbs
  [ -n "$tag" ] && [ -n "$name" ] || { err "tag/name required"; return 1; }

  line=$(awk -F'|' -v t="$tag" -v e="$name" '$1==t && $2==e {print; exit}' "$DISABLED_DB" 2>/dev/null)
  [ -n "$line" ] || { err "User '$name' not in disabled store."; return 1; }
  secret=$(printf '%s' "$line" | cut -d'|' -f3)
  proto=$(printf '%s' "$line" | cut -d'|' -f4)
  [ -n "$secret" ] || { err "Corrupt disabled entry."; return 1; }
  proto=${proto:-$(client_proto_of "$tag")}

  # Already live?
  if jq -e --arg t "$tag" --arg n "$name" \
      '.inbounds[]|select(.tag==$t).settings.clients[]|select(.email==$n)' \
      "$XRAY_CFG" >/dev/null 2>&1; then
    warn "Already live — cleaning disabled entry only."
    grep -v "^${tag}|${name}|" "$DISABLED_DB" > "${DISABLED_DB}.tmp" 2>/dev/null || true
    mv -f "${DISABLED_DB}.tmp" "$DISABLED_DB" 2>/dev/null || true
    return 0
  fi

  # Persist to disk
  if [ "$proto" = trojan ]; then
    cfg_apply_disk --arg t "$tag" --arg n "$name" --arg s "$secret" \
      '(.inbounds[]|select(.tag==$t).settings.clients) += [{password:$s,email:$n,level:0}]' || return 1
  else
    cfg_apply_disk --arg t "$tag" --arg n "$name" --arg s "$secret" \
      '(.inbounds[]|select(.tag==$t).settings.clients) += [{id:$s,email:$n,level:0}]' || return 1
  fi

  if xray_api_add_user "$tag" "$name" "$secret" "$proto"; then
    ok "ENABLED '$name' on $tag — live, no restart."
  else
    if [ "${CC_BATCH:-0}" = 1 ]; then
      CC_RESTART_PENDING=1
      ok "ENABLED '$name' on $tag — takes effect at the single Xray restart after this batch."
    else
      info "Applying enable with a quick Xray restart..."
      systemctl restart xray >/dev/null 2>&1 && wait_active xray 15 || {
        err "Xray restart failed after enable."; return 1
      }
      ok "ENABLED '$name' after restart."
    fi
  fi

  grep -v "^${tag}|${name}|" "$DISABLED_DB" > "${DISABLED_DB}.tmp" 2>/dev/null || true
  mv -f "${DISABLED_DB}.tmp" "$DISABLED_DB" 2>/dev/null || true
}

# Permanent delete (live + disabled + expiry)
delete_client_permanent() {
  local tag=$1 name=$2 was_live=0
  ensure_client_dbs
  [ -n "$tag" ] && [ -n "$name" ] || return 1

  # Live?
  if jq -e --arg t "$tag" --arg n "$name" \
      '.inbounds[]|select(.tag==$t).settings.clients[]|select(.email==$n)' \
      "$XRAY_CFG" >/dev/null 2>&1; then
    was_live=1
    cfg_apply_disk --arg t "$tag" --arg n "$name" \
      '(.inbounds[]|select(.tag==$t).settings.clients) |= map(select(.email!=$n))' || return 1
    xray_api_rm_user "$tag" "$name" 2>/dev/null || true
  fi

  # Disabled store
  if [ -f "$DISABLED_DB" ]; then
    grep -v "^${tag}|${name}|" "$DISABLED_DB" > "${DISABLED_DB}.tmp" 2>/dev/null || true
    mv -f "${DISABLED_DB}.tmp" "$DISABLED_DB" 2>/dev/null || true
  fi
  # Expiry
  if [ -f "$EXPIRY_DB" ]; then
    grep -v "^${tag}|${name}|" "$EXPIRY_DB" > "${EXPIRY_DB}.tmp" 2>/dev/null || true
    mv -f "${EXPIRY_DB}.tmp" "$EXPIRY_DB" 2>/dev/null || true
  fi
  if [ "$was_live" = 1 ]; then
    if [ "${CC_BATCH:-0}" = 1 ]; then
      CC_RESTART_PENDING=1
    else
      info "Closing remaining sessions with a short Xray restart (every client reconnects within seconds)..."
      systemctl restart xray >/dev/null 2>&1 && wait_active xray 15 \
        || warn "Xray restart failed — open sessions of the deleted user stay up until Xray restarts."
    fi
  fi
  ok "PERMANENTLY DELETED '$name' from $tag (config and records$( [ "$was_live" = 1 ] && echo '; open sessions end with the Xray restart' ))."
}

# Kick = end the live sessions of a user while the account stays valid.
# rmu + adu does NOT do that (established connections survive), so the only real way is a short Xray restart.
kick_client_sessions() {
  local tag=$1 name=$2
  [ -n "$(client_secret_of "$tag" "$name")" ] || { err "User '$name' is not live on $tag."; return 1; }
  if [ "${CC_BATCH:-0}" = 1 ]; then
    CC_RESTART_PENDING=1
    ok "KICK queued for '$name' — its sessions end at the single Xray restart after this batch; the account stays ACTIVE."
    return 0
  fi
  info "Ending the sessions with a short Xray restart (every connected client reconnects within seconds)..."
  if systemctl restart xray >/dev/null 2>&1 && wait_active xray 15; then
    ok "KICKED '$name' — all live sessions ended; the account stays ACTIVE and the client can reconnect at once."
    return 0
  fi
  err "Kick failed: Xray did not restart."; return 1
}

# ═══════════════════════════════════════════════════════════════════════════
# CONNECTION CONTROL — one sequential wizard:  ① action  →  ② protocol  →  ③ user(s)
# This is the ONLY place that disables / enables / deletes / kicks / renews / resets users.
# The per-protocol menus only add users and show links.
# ═══════════════════════════════════════════════════════════════════════════
CC_CAND=(); CC_LINE=(); CC_SEL=()

cc_proto_label() {
  case $1 in
    vless-ws) echo "VLESS" ;;  vmess-ws) echo "VMess" ;;  trojan-ws) echo "Trojan" ;;
    ss-ws) echo "Shadowsocks" ;;  ssh) echo "SSH-WS" ;;  *) echo "$1" ;;
  esac
}
cc_action_label() {
  case $1 in
    disable) echo "Disable" ;;  enable) echo "Enable" ;;  delete) echo "Delete" ;;
    kick) echo "Kick" ;;  renew) echo "Extend time" ;;  reset) echo "Reset key" ;;  *) echo "$1" ;;
  esac
}

# human bytes
hbytes() {
  awk -v b="${1:-0}" 'BEGIN{ split("B KB MB GB TB",u," "); i=1; while (b>=1024 && i<5) { b/=1024; i++ }
    if (i==1) printf "%d %s", b, u[i]; else printf "%.1f %s", b, u[i] }'
}

# "user<TAB>uplink<TAB>downlink" bytes per Xray user since the last Xray start.
xray_traffic_rows() {
  [ -x "$XRAY_BIN" ] || return 0
  timeout 5 "$XRAY_BIN" api statsquery --server="127.0.0.1:${XRAY_API_PORT:-10085}" -pattern "user>>>" 2>/dev/null \
    | jq -r '[.stat[]? | select((.name // "") | test("^user>>>.+>>>traffic>>>(uplink|downlink)$"))
              | {e:(.name|split(">>>")[1]), d:(.name|split(">>>")[3]), v:((.value // 0)|tonumber)}]
             | group_by(.e)[]
             | "\(.[0].e)\t\(map(select(.d=="uplink").v)|add // 0)\t\(map(select(.d=="downlink").v)|add // 0)"' 2>/dev/null
}

cc_is_disabled() { [ -s "$DISABLED_DB" ] && awk -F'|' -v t="$1" -v e="$2" '$1==t && $2==e {f=1} END{exit !f}' "$DISABLED_DB"; }

# 'YYYY-MM-DD' account expiry of a tunnel-only SSH user ("" = never)
ssh_expiry_of() {
  local d
  d=$(LC_ALL=C chage -l "$1" 2>/dev/null | sed -n 's/^Account expires[[:space:]]*:[[:space:]]*//p')
  case $d in ""|never) return 0 ;; esac
  date -d "$d" +%F 2>/dev/null || true
}
ssh_expired() {   # 0 when the account expiry date has been reached
  local e today
  e=$(ssh_expiry_of "$1"); [ -n "$e" ] || return 1
  today=$(date +%F)
  ! [[ $e > $today ]]
}

ssh_is_tunnel_user() { [ -n "${1:-}" ] && ssh_users | gq -Fx -- "$1"; }

# Fill CC_CAND (names) + CC_LINE (one display line each) with the users that make sense for
# <action> on <proto>. Needs refresh_online_set (ONL_*) and SSH sessions (CC_SSESS) beforehand.
CC_SSESS=""
cc_build() {
  local action=$1 tag=$2 n st exp left k locked line txt on_ok
  CC_CAND=(); CC_LINE=()
  if [ "$tag" = ssh ]; then
    while IFS= read -r n; do
      [ -n "$n" ] || continue
      k=$(awk -v u="$n" '$1==u {print $2}' <<< "$CC_SSESS")
      locked=0; ssh_user_locked "$n" && locked=1
      case $action in
        disable) [ "$locked" = 0 ] || continue ;;
        enable)  [ "$locked" = 1 ] || continue ;;
        kick)    [ -n "$k" ] || continue ;;
      esac
      exp=$(ssh_expiry_of "$n")
      txt=""
      if [ "$locked" = 1 ]; then txt+="${Y}⊘ DISABLED${N}  "; fi
      if [ -n "$exp" ]; then
        if ssh_expired "$n"; then txt+="${R}EXPIRED ${exp}${N}  "; else txt+="${D}until ${exp}${N}  "; fi
      else
        txt+="${D}no expiry${N}  "
      fi
      if [ -n "$k" ]; then txt+="${G}● ONLINE${N} ${D}(${k} conn)${N}"; else txt+="${D}○ offline${N}"; fi
      CC_CAND+=("$n"); CC_LINE+=("$txt")
    done < <(ssh_users)
    return 0
  fi
  # Xray protocols: live users first, then the disabled store
  local -a names=() states=()
  while IFS=$'\t' read -r n _; do
    [ -n "$n" ] || continue
    names+=("$n"); states+=(live)
  done < <(clients_of "$tag")
  if [ -s "$DISABLED_DB" ]; then
    while IFS='|' read -r st n _; do
      [ "$st" = "$tag" ] && [ -n "$n" ] || continue
      names+=("$n"); states+=(off)
    done < "$DISABLED_DB"
  fi
  local i
  for i in "${!names[@]}"; do
    n=${names[$i]}; st=${states[$i]}
    on_ok=0; [ "$ONL_READY" = 1 ] && grep -Fxq -- "$n" <<< "$ONL_SET" && on_ok=1
    case $action in
      disable) [ "$st" = live ] || continue ;;
      enable)  [ "$st" = off ] || continue ;;
      kick)    [ "$st" = live ] || continue
               if [ "$ONL_READY" = 1 ] && [ "$on_ok" = 0 ]; then continue; fi ;;
    esac
    exp=$(awk -F'|' -v t="$tag" -v e="$n" '$1==t && $2==e {print $3; exit}' "$EXPIRY_DB" 2>/dev/null)
    txt=""
    if [ "$st" = off ]; then txt+="${Y}⊘ DISABLED${N}  "; fi
    if [ -n "$exp" ]; then
      left=$(expiry_left_text "$exp" 2>/dev/null || echo "?")
      if [ "$left" = EXPIRED ]; then txt+="${R}EXPIRED${N}  "
      elif [ "$left" = INVALID ]; then txt+="${Y}expiry unreadable (Extend time fixes it)${N}  "
      else txt+="${D}${left} left${N}  "; fi
    else
      txt+="${D}no expiry${N}  "
    fi
    if [ "$st" = live ]; then txt+="$(online_tag "$n")"; fi
    CC_CAND+=("$n"); CC_LINE+=("$txt")
  done
  return 0
}

# "1 3 5-7", "1,2", "all"  →  CC_SEL (1-based, unique, in order). Returns 1 when invalid.
cc_parse_sel() {
  local s=${1,,} cnt=$2 tok a b i
  local -A seen=()
  CC_SEL=()
  s=${s//,/ }
  case $s in
    all|a|"*") for ((i=1; i<=cnt; i++)); do CC_SEL+=("$i"); done; [ "$cnt" -gt 0 ]; return ;;
  esac
  for tok in $s; do
    if [[ $tok =~ ^[0-9]+$ ]]; then a=$((10#$tok)); b=$a
    elif [[ $tok =~ ^([0-9]+)-([0-9]+)$ ]]; then a=$((10#${BASH_REMATCH[1]})); b=$((10#${BASH_REMATCH[2]}))
    else return 1; fi
    [ "$a" -ge 1 ] && [ "$a" -le "$b" ] && [ "$b" -le "$cnt" ] || return 1
    for ((i=a; i<=b; i++)); do
      [ -n "${seen[$i]:-}" ] || { seen[$i]=1; CC_SEL+=("$i"); }
    done
  done
  [ "${#CC_SEL[@]}" -gt 0 ]
}

cc_online_line() {
  local x s
  refresh_online_set
  CC_SSESS=$(online_ssh_sessions)
  x=$(sed '/^$/d' <<< "$ONL_SET" | wc -l)
  s=$(sed '/^$/d' <<< "$CC_SSESS" | wc -l)
  if [ "$ONL_READY" = 1 ]; then
    printf '  %sONLINE NOW%s  %s%s%s   %sXray %s · SSH %s%s\n' "$D" "$N" "$G$B" "$((x + s))" "$N" "$D" "$x" "$s" "$N"
  else
    printf '  %sONLINE NOW%s  %s%s%s   %s(Xray counter off — run: finixo repair)  SSH %s%s\n' "$D" "$N" "$G$B" "$s" "$N" "$Y" "$s" "$N"
  fi
}

# ── Actions on ONE user ───────────────────────────────────────────────────
# renew: time to add comes from CC_DUR_SECS (asked once per batch)
cc_set_expiry() {   # tag name ISO
  ensure_client_dbs
  db_drop "$EXPIRY_DB" "$1" "$2"
  printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$EXPIRY_DB"
  chmod 600 "$EXPIRY_DB" 2>/dev/null || true
}

cc_renew_xray() {
  local tag=$1 name=$2 cur cts now base new iso
  now=$(date +%s); base=$now
  cur=$(awk -F'|' -v t="$tag" -v e="$name" '$1==t && $2==e {print $3; exit}' "$EXPIRY_DB" 2>/dev/null)
  if [ -n "$cur" ]; then
    [[ $cur =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && cur="${cur}T23:59:59"
    cts=$(date -d "$cur" +%s 2>/dev/null || echo 0)
    [ "$cts" -gt "$now" ] && base=$cts
  fi
  new=$((base + CC_DUR_SECS))
  iso=$(date -d "@$new" +%Y-%m-%dT%H:%M:%S) || { err "date failed"; return 1; }
  cc_set_expiry "$tag" "$name" "$iso"
  ok "RENEWED '$name' ($(cc_proto_label "$tag")) — now valid until $iso  (+${DUR_HUMAN})."
}

ssh_renew_user() {
  local u=$1 cur today base days new
  ssh_is_tunnel_user "$u" || { err "'$u' is not a tunnel-only user; refusing."; return 1; }
  today=$(date +%F); base=$today
  cur=$(ssh_expiry_of "$u")
  if [ -n "$cur" ] && [[ $cur > $today ]]; then base=$cur; fi
  days=$(( (CC_DUR_SECS + 86399) / 86400 ))
  new=$(date -d "$base + $days days" +%F) || return 1
  chage -E "$new" "$u" || { err "chage failed for '$u'."; return 1; }
  ok "RENEWED '$u' (SSH-WS) — account valid until $new  (+${days}d; SSH expiry is per whole day)."
}

cc_reset_xray() {
  local tag=$1 name=$2 new proto tmp
  proto=$(client_proto_of "$tag")
  case $tag in trojan-ws) new=$(rand_hex 16) ;; *) new=$(new_uuid) ;; esac
  [ -n "$new" ] || { err "Could not generate a new key."; return 1; }
  if [ -n "$(client_secret_of "$tag" "$name")" ]; then
    cfg_apply_disk --arg t "$tag" --arg n "$name" --arg s "$new" \
      '(.inbounds[]|select(.tag==$t).settings.clients[]|select(.email==$n))
         |= (if has("password") then .password=$s else .id=$s end)' || return 1
    # A key reset is usually a leaked-key response: old sessions must end too, and only a restart does that.
    if [ "${CC_BATCH:-0}" = 1 ]; then
      CC_RESTART_PENDING=1
      ok "NEW KEY for '$name' — the old key stops working at the Xray restart after this batch."
    else
      info "Applying the new key with a short Xray restart (the old key's sessions end; clients reconnect within seconds)..."
      systemctl restart xray >/dev/null 2>&1 && wait_active xray 15 || { err "Xray restart failed after the key reset."; return 1; }
      ok "NEW KEY for '$name' — the old key no longer works and its sessions are closed."
    fi
  elif cc_is_disabled "$tag" "$name"; then
    tmp=$(mktemp "${DISABLED_DB}.XXXXXX") || return 1
    awk -F'|' -v OFS='|' -v t="$tag" -v e="$name" -v s="$new" '$1==t && $2==e {$3=s} {print}' "$DISABLED_DB" > "$tmp" \
      && chmod 600 "$tmp" && mv -f "$tmp" "$DISABLED_DB" || { rm -f "$tmp"; err "Could not update the disabled store."; return 1; }
    ok "NEW KEY stored for disabled '$name' (applies when you enable it)."
  else
    err "User '$name' not found."; return 1
  fi
  load_conf
  printf '  %s%s%s\n' "$C" "$(mklink "$tag" "$name" "$new")" "$N"
  info "Send the new link to the user — the old one no longer works."
}

ssh_reset_user() {
  local u=$1 pw was=0
  ssh_is_tunnel_user "$u" || { err "'$u' is not a tunnel-only user; refusing."; return 1; }
  ssh_user_locked "$u" && was=1
  read -r -s -p "  New password for '$u' (empty = random 16 hex, min 12 chars): " pw || return 1; echo
  pw=${pw:-$(rand_hex 16)}
  [ "${#pw}" -ge 12 ] || { err "The password must have at least 12 characters."; return 1; }
  printf '%s:%s\n' "$u" "$pw" | chpasswd || { err "chpasswd failed."; return 1; }
  if [ "$was" = 1 ]; then usermod -L "$u" 2>/dev/null || true; fi   # a reset must never silently re-enable
  pkill -KILL -u "$u" 2>/dev/null || true
  ok "NEW PASSWORD for '$u' — old sessions closed$( [ "$was" = 1 ] && echo '; account is still DISABLED' )."
  load_conf; ssh_info "$u" "$pw"
}

# SSH-WS user control — tunnel-only users ONLY (OS logins are never touched).
ssh_disable_user() {
  local u=$1 k
  ssh_is_tunnel_user "$u" || { err "'$u' is not a tunnel-only user; refusing."; return 1; }
  if ssh_user_locked "$u"; then warn "'$u' is already disabled."; return 0; fi
  k=$(ssh_sessions_of "$u")
  usermod -L "$u" || { err "Could not lock '$u'."; return 1; }
  pkill -KILL -u "$u" 2>/dev/null || true
  sleep 0.3
  if [ -n "$(ssh_sessions_of "$u")" ]; then warn "Some sessions of '$u' are still closing."; fi
  ok "DISABLED '$u' (SSH-WS) — login locked, ${k:-0} live connection(s) killed."
}
ssh_enable_user() {
  local u=$1
  ssh_is_tunnel_user "$u" || { err "'$u' is not a tunnel-only user; refusing."; return 1; }
  if ! ssh_user_locked "$u"; then warn "'$u' is not disabled."; return 0; fi
  usermod -U "$u" || { err "Could not unlock '$u'."; return 1; }
  ok "ENABLED '$u' (SSH-WS) — can log in again."
}
ssh_kick_user() {
  local u=$1 k
  ssh_is_tunnel_user "$u" || { err "'$u' is not a tunnel-only user; refusing."; return 1; }
  k=$(ssh_sessions_of "$u")
  if [ -z "$k" ]; then warn "'$u' has no live connection."; return 0; fi
  pkill -KILL -u "$u" 2>/dev/null || true
  ok "KICKED '$u' (SSH-WS) — ${k} connection(s) closed; the user stays ACTIVE and may reconnect."
}
ssh_delete_user() {
  local u=$1
  ssh_is_tunnel_user "$u" || { err "'$u' is not a tunnel-only user; refusing."; return 1; }
  pkill -KILL -u "$u" 2>/dev/null || true
  sleep 0.3
  if userdel "$u"; then ok "DELETED '$u' (SSH-WS) — account removed, sessions killed."; else err "userdel failed for '$u'."; return 1; fi
}

# Shadowsocks has ONE shared key (no per-user accounts): the only control action is a new key.
cc_ss_reset() {
  local m s
  m=$(ss_method)
  [ -n "$m" ] || { err "Could not read the Shadowsocks cipher (config damaged?)."; return 1; }
  s=$(ss_gen_password "$m") || { err "Could not generate a key."; return 1; }
  if cfg_apply --arg p "$s" '(.inbounds[]|select(.tag=="ss-ws").settings.password)=$p'; then
    ok "NEW Shadowsocks key — every client must import the new link:"; show_ss_links
  else
    return 1
  fi
}

# Run <action> on one user of <tag>
cc_apply_one() {
  local action=$1 tag=$2 name=$3 cnt
  if [ "$tag" = ssh ]; then
    case $action in
      disable) ssh_disable_user "$name" ;;  enable) ssh_enable_user "$name" ;;
      delete)  ssh_delete_user "$name" ;;   kick)   ssh_kick_user "$name" ;;
      renew)   ssh_renew_user "$name" ;;    reset)  ssh_reset_user "$name" ;;
    esac
    return
  fi
  case $action in
    disable|delete)
      cnt=$(count_xray_clients "$tag")
      if [ "$name" = default ] && [ "${cnt:-0}" -le 1 ] && [ -n "$(client_secret_of "$tag" "$name")" ]; then
        warn "Refusing to $action the only remaining 'default' user on $(cc_proto_label "$tag")."; return 1
      fi ;;
  esac
  case $action in
    disable) disable_client "$tag" "$name" ;;
    enable)  enable_client "$tag" "$name" ;;
    delete)  delete_client_permanent "$tag" "$name" ;;
    kick)    kick_client_sessions "$tag" "$name" ;;
    renew)   cc_renew_xray "$tag" "$name" ;;
    reset)   cc_reset_xray "$tag" "$name" ;;
  esac
}

# ── Overview / purge ──────────────────────────────────────────────────────
cc_overview() {
  local rows e up dn
  list_all_connections
  rows=$(xray_traffic_rows | sort -t$'\t' -k3,3nr)
  echo
  echo -e "  ${W}━━ TRAFFIC per Xray user ${D}(since the last Xray start)${W} ━━${N}"
  if [ -z "$rows" ]; then
    echo -e "  ${D}(no traffic recorded yet)${N}"
  else
    printf '  %s%-22s %12s %12s%s\n' "$D" USER "↑ UPLOAD" "↓ DOWNLOAD" "$N"
    while IFS=$'\t' read -r e up dn; do
      [ -n "$e" ] || continue
      printf '  %-22s %12s %12s\n' "$e" "$(hbytes "$up")" "$(hbytes "$dn")"
    done <<< "$rows"
  fi
}

cc_purge_expired() {
  local nx=0 tag n exp left u ns=0 c
  local -a ex_ssh=()
  ensure_client_dbs
  while IFS='|' read -r tag n exp; do
    [ -n "$tag" ] && [ -n "$n" ] && [ -n "$exp" ] || continue
    left=$(expiry_left_text "$exp" 2>/dev/null || echo "?")
    [ "$left" = EXPIRED ] && nx=$((nx+1))
  done < "$EXPIRY_DB"
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    if ssh_expired "$u"; then ex_ssh+=("$u"); fi
  done < <(ssh_users)
  ns=${#ex_ssh[@]}
  if [ "$nx" -eq 0 ] && [ "$ns" -eq 0 ]; then ok "Nothing expired — every user is still valid."; return 0; fi
  echo -e "  ${W}Expired:${N} ${nx} Xray user(s), ${ns} SSH-WS user(s)"
  [ "$ns" -gt 0 ] && echo -e "  ${D}SSH-WS: ${ex_ssh[*]}${N}"
  if [ "${FINIXO_YES:-0}" != 1 ]; then
    read -r -p "  Remove all of them permanently? [y/N] " c || return 0
    [[ ${c,,} == y ]] || { warn "Cancelled."; return 0; }
  fi
  [ "$nx" -gt 0 ] && purge_expired_clients
  for u in "${ex_ssh[@]}"; do ssh_delete_user "$u" || true; done
  ok "Expired users removed."
}

# ── The wizard ────────────────────────────────────────────────────────────
connection_control_menu() {
  # INT/TERM only — do NOT trap RETURN (fires on every nested function return and breaks CC_BATCH)
  trap 'CC_BATCH=0; cc_flush_restart || true; trap - INT TERM; exit 130' INT TERM
  local step=1 act="" proto="" ans i n cnt c ok_n fail_n total tag
  local -a protos
  ensure_client_dbs; load_conf
  while true; do
    case $step in
    1)  # ── ① choose the action ──
      clear 2>/dev/null || true
      u_title "CONNECTION CONTROL"
      cc_online_line
      echo
      echo -e "  ${W}① What do you want to do?${N}"
      echo
      echo -e "   ${C}1${N}  Disable     ${D}stop access + kill live sessions${N}"
      echo -e "   ${C}2${N}  Enable      ${D}restore a disabled user${N}"
      echo -e "   ${C}3${N}  Delete      ${D}remove permanently${N}"
      echo -e "   ${C}4${N}  Kick        ${D}end live sessions, user stays active${N}"
      echo -e "   ${C}5${N}  Extend time ${D}add days/hours to a user (on top of the time left, or from now if expired)${N}"
      echo -e "   ${C}6${N}  Reset key   ${D}new UUID / password / Shadowsocks key${N}"
      echo -e "   ${D}─────────────────────────────────────────${N}"
      echo -e "   ${C}7${N}  Overview    ${D}all users, status and traffic${N}"
      echo -e "   ${C}8${N}  Purge       ${D}remove every expired user${N}"
      echo -e "   ${C}0${N}  Back"
      echo
      read -r -p "  > " ans || return 0
      case ${ans,,} in
        1) act=disable ;; 2) act=enable ;; 3) act=delete ;; 4) act=kick ;; 5) act=renew ;; 6) act=reset ;;
        7) clear 2>/dev/null || true; u_title "OVERVIEW"; cc_overview; echo; pause; continue ;;
        8) echo; cc_purge_expired; echo; pause; continue ;;
        0|q|b) return 0 ;;
        *) continue ;;
      esac
      step=2 ;;

    2)  # ── ② choose the protocol ──
      clear 2>/dev/null || true
      u_title "CONNECTION CONTROL"
      cc_online_line
      echo
      echo -e "  ${W}② $(cc_action_label "$act") — which protocol?${N}"
      echo
      protos=(vless-ws ss-ws vmess-ws trojan-ws ssh)
      i=0
      for tag in "${protos[@]}"; do
        i=$((i+1))
        if [ "$tag" = ss-ws ]; then
          if [ "$act" = reset ]; then
            printf '   %s%d%s  %-12s %s1 shared key%s\n' "$C" "$i" "$N" "$(cc_proto_label "$tag")" "$D" "$N"
          else
            printf '   %s%d%s  %-12s %sone shared key — no per-user accounts%s\n' "$D" "$i" "$N" "$(cc_proto_label "$tag")" "$D" "$N"
          fi
          continue
        fi
        cc_build "$act" "$tag"
        cnt=${#CC_CAND[@]}
        if [ "$cnt" -gt 0 ]; then
          printf '   %s%d%s  %-12s %s%d user(s)%s\n' "$C" "$i" "$N" "$(cc_proto_label "$tag")" "$G" "$cnt" "$N"
        else
          printf '   %s%d  %-12s —%s\n' "$D" "$i" "$(cc_proto_label "$tag")" "$N"
        fi
      done
      echo -e "   ${C}0${N}  Back"
      echo
      read -r -p "  > " ans || return 0
      case ${ans,,} in
        0|q|b|"") step=1; continue ;;
      esac
      [[ $ans =~ ^[1-5]$ ]] || continue
      proto=${protos[$((ans-1))]}
      if [ "$proto" = ss-ws ]; then
        if [ "$act" = reset ]; then
          echo
          read -r -p "  Generate a NEW Shadowsocks key? Every client must re-import it. [y/N] " c || return 0
          if [[ ${c,,} == y ]] || [ "${FINIXO_YES:-0}" = 1 ]; then cc_ss_reset; echo; pause; step=1; fi
        else
          echo; warn "Shadowsocks has a single shared key — the only control action is 'Reset key'."; pause
        fi
        continue
      fi
      step=3 ;;

    3)  # ── ③ choose the user(s) ──
      clear 2>/dev/null || true
      u_title "CONNECTION CONTROL"
      cc_online_line
      echo
      echo -e "  ${W}③ $(cc_action_label "$act") — $(cc_proto_label "$proto") — which user?${N}"
      echo
      cc_build "$act" "$proto"
      cnt=${#CC_CAND[@]}
      if [ "$cnt" -eq 0 ]; then
        warn "Nobody to $(cc_action_label "$act" | tr 'A-Z' 'a-z') on $(cc_proto_label "$proto")."
        pause; step=2; continue
      fi
      for i in "${!CC_CAND[@]}"; do
        printf '   %s%2d%s  %-22s %s\n' "$C" "$((i+1))" "$N" "${CC_CAND[$i]}" "${CC_LINE[$i]}"
      done
      echo
      if [ "$act" = reset ]; then
        echo -e "  ${D}Enter one number · 0 = back${N}"
      else
        echo -e "  ${D}Enter a number, several (1 3 5 or 2-4) or 'all' · 0 = back${N}"
      fi
      read -r -p "  > " ans || return 0
      case ${ans,,} in 0|q|b|"") step=2; continue ;; esac
      if ! cc_parse_sel "$ans" "$cnt"; then err "Invalid selection."; pause; continue; fi
      if [ "$act" = reset ] && [ "${#CC_SEL[@]}" -ne 1 ]; then err "Reset key works on one user at a time."; pause; continue; fi
      local -a pick=()
      for i in "${CC_SEL[@]}"; do pick+=("${CC_CAND[$((i-1))]}"); done
      total=${#pick[@]}

      if [ "$act" = renew ]; then
        echo -e "  ${D}Adds to the remaining time (or starts from now if expired). Examples: 30 | 7d | 12h | 1d6h${N}"
        read -r -p "  Add how much time? [30d]: " c || return 0; c=${c:-30}
        if ! parse_duration "$c"; then err "Invalid duration (e.g. 7d, 12h, 1d6h, 90m)."; pause; continue; fi
        CC_DUR_SECS=$DUR_SECS
      fi

      echo
      echo -e "  ${W}$(cc_action_label "$act")${N} ${total} user(s) on $(cc_proto_label "$proto"): ${C}${pick[*]}${N}"
      case $act in
        delete|disable|reset)
          if [ "${FINIXO_YES:-0}" != 1 ]; then
            read -r -p "  Confirm? [y/N] " c || return 0
            [[ ${c,,} == y ]] || { warn "Cancelled."; pause; continue; }
          fi ;;
      esac

      echo
      ok_n=0; fail_n=0; i=0
      [ "$proto" = ssh ] || CC_BATCH=1       # Xray protocols: queue the restart and do it ONCE at the end
      for n in "${pick[@]}"; do
        i=$((i+1))
        if cc_apply_one "$act" "$proto" "$n"; then ok_n=$((ok_n+1)); else fail_n=$((fail_n+1)); fi
      done
      CC_BATCH=0
      cc_flush_restart || fail_n=$((fail_n+1))
      echo
      if [ "$total" -gt 1 ] || [ "$fail_n" -gt 0 ]; then
        echo -e "  ${W}Done:${N} ${G}${ok_n} ok${N}$( [ "$fail_n" -gt 0 ] && printf ', %s%s failed%s' "$R" "$fail_n" "$N" )"
      fi
      pause
      step=1 ;;
    esac
  done
}

# ── Per-protocol menus: add users + show links only (management lives in Connection Control) ──
proto_menu() {
  local tag=$1 label=$2 c
  while true; do
    clear 2>/dev/null || true
    u_title "${label^^} · WebSocket"
    echo "  [1] Add user"
    echo "  [2] List users + links"
    echo "  [0] Back"
    echo -e "  ${D}Disable / delete / kick / renew / reset key → Connection Control (menu $(menu_no 'Connection Control'))${N}"
    read -r -p "  > " c || return 0
    case $c in
      1) add_client "$tag"; pause ;;
      2) list_clients "$tag"; links_note; pause ;;
      0) return 0 ;;
    esac
  done
}


links_note() {
  load_conf
  echo
  if ! client_tls; then
    info "These links use plain WebSocket (no TLS) on port $REMOTE_PROXY_PORT."
  elif use_pin; then
    info "Certificate is self-signed and pinned in the links (pcs=). If your client has no"
    info "'certificate fingerprint' field, paste this SHA-256 there:"
    printf '     %s%s%s\n' "$W" "$(cert_sha256)" "$N"
  else
    info "TLS is verified normally: the remote proxy must present a valid certificate for the SNI."
  fi
}

show_ss_links() {
  local s
  load_conf
  s=$(ss_password)
  [ -n "$s" ] || { err "Could not read the Shadowsocks password."; return 1; }
  printf '  %sCipher: %s%s\n\n' "$W" "$(ss_method)" "$N"
  printf '  %sXray / sing-box style (v2rayN, v2rayNG, NekoBox, Hiddify):%s\n' "$W" "$N"
  printf '  %s%s%s\n' "$C" "$(mklink ss-ws default "$s")" "$N"
  if use_pin; then
    printf '\n  %s(The v2ray-plugin link is not shown: the plugin cannot pin a self-signed certificate.)%s\n' "$D" "$N"
  else
    printf '\n  %sSIP003 v2ray-plugin style (shadowsocks-rust, Shadowsocks Android):%s\n' "$W" "$N"
    printf '  %s%s%s\n' "$C" "$(mklink ss-plugin default "$s")" "$N"
    if [ "$CLIENT_SNI" != "$CLIENT_HOST" ] && client_tls; then
      warn "v2ray-plugin uses one value for SNI and Host; use the first link for a split profile."
    fi
  fi
}

ss_menu() {
  local c s m nm
  while true; do
    clear 2>/dev/null || true
    u_title "SHADOWSOCKS 2022 · WebSocket"
    echo "  Cipher: $(ss_method)"
    echo "  [1] Show links"
    echo "  [2] Change cipher"
    echo -e "  ${D}New key → Connection Control (menu $(menu_no 'Connection Control')) › Reset key › Shadowsocks${N}"
    echo "  [0] Back"
    read -r -p "  > " c || return 0
    case $c in
      1) show_ss_links; pause ;;
      2) echo "    a) 2022-blake3-aes-256-gcm        (servers/clients with AES hardware)"
         echo "    b) 2022-blake3-chacha20-poly1305  (phones / CPUs without AES hardware)"
         echo "    c) 2022-blake3-aes-128-gcm        (lightest)"
         read -r -p "  Cipher [a/b/c]: " nm
         case $nm in
           a) nm=2022-blake3-aes-256-gcm ;;
           b) nm=2022-blake3-chacha20-poly1305 ;;
           c) nm=2022-blake3-aes-128-gcm ;;
           *) err "Cancelled."; pause; continue ;;
         esac
         s=$(ss_new_key "$nm") || { err "Could not generate a key"; pause; continue; }
         if cfg_apply --arg m "$nm" --arg p "$s" '(.inbounds[]|select(.tag=="ss-ws").settings) |= (.method=$m | .password=$p)'; then
           ok "Cipher changed to $nm. New links:"; show_ss_links
         fi
         pause ;;
      0) return 0 ;;
    esac
  done
}

kv() { printf '  %s%-13s:%s %s\n' "$W" "$1" "$N" "$2"; }

ssh_info() {
  load_conf
  local payload
  # Payload MUST use the exact current path ($WSP_SSH). Wrong path = HTTP 404.
  payload="GET ${WSP_SSH} HTTP/1.1[crlf]Host: ${CLIENT_HOST}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf]User-Agent: [ua][crlf][crlf]"
  echo -e "\n  ${W}━━ SSH-WS connection (HTTP Custom) ━━${N}"
  kv "Remote Proxy" "$REMOTE_PROXY"
  kv "TLS" "$(tls_mode_text)"
  client_tls && kv "TLS SNI" "$CLIENT_SNI"
  kv "WS Host" "$CLIENT_HOST"
  kv "Port" "$REMOTE_PROXY_PORT"
  kv "Path" "$WSP_SSH"
  if [ -n "${1:-}" ]; then kv "User" "$1"; kv "Pass" "${2:-}"; fi
  echo
  echo -e "  ${Y}⚠ Path in payload MUST be exactly: ${W}${WSP_SSH}${N}"
  echo -e "  ${D}(If you reinstalled, old paths like /cdn/assets/... no longer work)${N}"
  echo
  echo -e "  ${W}Payload (paste as ONE line in HTTP Custom):${N}"
  printf '  %s%s%s\n' "$C" "$payload" "$N"
  echo
  echo -e "  ${D}After HTTP 101 → raw TCP to OpenSSH (not RFC 6455 framing).${N}"
  echo -e "  ${D}Server/SNI/Host = ${CLIENT_HOST} · Proxy can be wr.x.com:443 or your CDN.${N}"
}


ssh_add() {
  local u days pw exp
  read -r -p "  Username (a-z, 0-9, _-, max 24): " u
  [[ $u =~ ^[a-z_][a-z0-9_-]{0,23}$ ]] || { err "Invalid username."; return 1; }
  id "$u" >/dev/null 2>&1 && { err "That user already exists on this system."; return 1; }
  echo -e "  ${D}Duration: 30 | 7d | 12h | 1d6h | 90m${N}"
  read -r -p "  Valid for [30d]: " dur; dur=${dur:-30}
  if ! parse_duration "$dur"; then err "Invalid duration."; return 1; fi
  days=$(( (DUR_SECS + 86399) / 86400 ))  # chage needs whole days (ceil)
  read -r -s -p "  Password (empty = random 16 hex): " pw; echo; pw=${pw:-$(rand_hex 16)}
  [ "${#pw}" -ge 12 ] || { err "The password must have at least 12 characters."; return 1; }
  exp=$(date -d "+$days days" +%F) || return 1
  useradd -d /nonexistent -M -g "$SSH_GROUP" -s /bin/bash -e "$exp" "$u" || { err "useradd failed"; return 1; }
  if ! printf '%s:%s\n' "$u" "$pw" | chpasswd; then userdel "$u" >/dev/null 2>&1 || true; err "chpasswd failed"; return 1; fi
  ok "SSH-WS user created (expires $exp)"; ssh_info "$u" "$pw"
}

ssh_list() {
  local u exp sess k st
  sess=$(online_ssh_sessions)
  printf '  %-24s %-16s %s\n' USER EXPIRES ONLINE
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    exp=$(chage -l "$u" 2>/dev/null | awk -F': ' '/Account expires/{print $2}')
    k=$(awk -v u="$u" '$1==u {print $2}' <<< "$sess")
    if ssh_user_locked "$u"; then st="${Y}⊘ DISABLED${N}"
    elif [ -n "$k" ]; then st="${G}● online (${k})${N}"; else st="${D}○ offline${N}"; fi
    printf '  %-24s %-16s %s\n' "$u" "${exp:-never}" "$st"
  done < <(ssh_users)
}

# ── SSH-WS user control — tunnel-only users ONLY (OS logins are never touched) ──
# Disable = lock the password (no new logins) + kill live sessions; Enable = unlock.
ssh_user_locked() {
  local st
  st=$(passwd -S "$1" 2>/dev/null | awk '{print $2}')
  [ "$st" = "L" ] || [ "$st" = "LK" ]
}

ssh_sessions_of() { online_ssh_sessions | awk -v u="$1" '$1==u {print $2}'; }

ssh_menu() {
  local c
  while true; do
    clear 2>/dev/null || true
    u_title "SSH · WebSocket"
    printf '  %s[1]%s  Add user\n' "$C" "$N"
    printf '  %s[2]%s  List users (live status)\n' "$C" "$N"
    printf '  %s[3]%s  Connection info + payload\n' "$C" "$N"
    printf '  %s[4]%s  Edit login banner\n' "$C" "$N"
    printf '  %s[0]%s  Back\n' "$D" "$N"
    printf '\n  %sDisable / enable / kick / renew / reset / delete → Connection Control (menu %s)%s\n' "$D" "$(menu_no 'Connection Control')" "$N"
    read -r -p "  > " c || return 0
    case $c in
      1) ssh_add; pause ;;
      2) ssh_list; pause ;;
      3) ssh_info; pause ;;
      4) ssh_banner_edit; pause ;;
      0) return 0 ;;
    esac
  done
}

client_profile_summary() {
  load_conf
  kv "Server" "$SERVER_ADDR${SERVER_IP:+  ($SERVER_IP)}"
  kv "Remote Proxy" "$REMOTE_PROXY"
  kv "TLS SNI" "$CLIENT_SNI"
  kv "WS Host" "$CLIENT_HOST"
  kv "Security" "$(tls_mode_text)"
}

show_vless_notls_links() {
  load_conf
  local n s p
  echo -e "\n${W}══ VLESS non-TLS (security=none) ══${N}\n"
  info "Same VLESS users; link forces security=none (WS on plain HTTP, usually :80)."
  info "Nginx already upgrades WebSocket on port 80 for path ${WSP_VLESS}."
  echo
  while IFS=$'\t' read -r n s; do
    [ -n "$n" ] || continue
    printf '  %s%s%s\n' "$W" "$n" "$N"
    printf '     %s%s%s\n' "$C" "$(mklink vless-ws "$n" "$s" none)" "$N"
  done < <(clients_of vless-ws)
  echo
  case "${REMOTE_PROXY_PORT:-443}" in
    443|8443|2053|2083|2087|2096) p=80 ;;
    *) p="${REMOTE_PROXY_PORT:-80}" ;;
  esac
  kv "Remote host" "$REMOTE_PROXY_HOST"
  kv "Port in link" "$p"
  kv "Host header" "$CLIENT_HOST"
  kv "Path" "$WSP_VLESS"
  echo
}

show_all_links() {
  load_conf
  local t u n s
  for t in vless-ws vmess-ws trojan-ws; do
    u=${t%-ws}; echo -e "\n${W}━━ ${u^^} (profile TLS mode) ━━${N}"; list_clients "$t"
  done
  echo -e "\n${W}━━ VLESS non-TLS (security=none, typically :80) ━━${N}"
  while IFS=$'\t' read -r n s; do
    [ -n "$n" ] || continue
    printf '  %s%s%s\n' "$W" "$n" "$N"
    printf '     %s%s%s\n' "$C" "$(mklink vless-ws "$n" "$s" none)" "$N"
  done < <(clients_of vless-ws)
  echo -e "\n${W}━━ SHADOWSOCKS 2022 ━━${N}"
  show_ss_links
  echo -e "\n${W}━━ SSH-WS ━━${N}"; ssh_info
  echo -e "\n${W}━━ ENDPOINT (client profile) ━━${N}"
  kv "Remote Proxy" "${REMOTE_PROXY}"
  kv "SNI" "${CLIENT_SNI}"
  kv "Host" "${CLIENT_HOST}"
  kv "Security" "$(tls_mode_text)"
  links_note
}

# Remote Proxy / SNI / Host — any domain or IP, any port
client_profile_menu() {
  load_conf
  clear 2>/dev/null || true
  echo -e "${C}══ Client endpoint ══${N}
"
  info "Remote / SNI / Host are locked to this server (policy since 1.4.0)."
  kv "Remote Proxy" "${REMOTE_PROXY:-not set}"
  kv "TLS SNI" "${CLIENT_SNI:-not set}"
  kv "WS Host" "${CLIENT_HOST:-not set}"
  kv "Security" "$(tls_mode_text 2>/dev/null || echo auto)"
  echo
  info "Links always use ${SERVER_ADDR}:443. Editing is disabled."
  pause
}

# ----------------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------------
# Self-test 4.0 — dense checklist (files, perms, services, TLS, WS, E2E, SSH, security)
self_test() {
  load_conf
  local fails=0 passes=0 warns=0 s name pth proto code want exposed st tlsflag perms
  local -a R3
  _t_ok()   { ok "$1"; passes=$((passes+1)); }
  _t_fail() { err "$1"; fails=$((fails+1)); }
  _t_warn() { warn "$1"; warns=$((warns+1)); }
  _t_chk()  { local _l=$1; shift; if "$@"; then _t_ok "$_l"; else _t_fail "$_l"; fi; }

  echo -e "\n${W}══ Finixo Gate $VERSION — full self-test ══${N}\n"
  [ -n "$SERVER_ADDR" ] || { err "Server address missing."; return 1; }

  # --- Binaries & paths ---
  _t_chk "xray binary executable" test -x "$XRAY_BIN"
  _t_chk "xray version runs" "$XRAY_BIN" version
  if command -v python3 >/dev/null 2>&1; then _t_ok "python3 present"; else _t_fail "python3 present"; fi
  if command -v nginx >/dev/null 2>&1; then _t_ok "nginx binary present"; else _t_fail "nginx binary present"; fi
  if command -v openssl >/dev/null 2>&1; then _t_ok "openssl present"; else _t_fail "openssl present"; fi
  if command -v jq >/dev/null 2>&1; then _t_ok "jq present"; else _t_fail "jq present"; fi
  if command -v curl >/dev/null 2>&1; then _t_ok "curl present"; else _t_fail "curl present"; fi
  if command -v sshd >/dev/null 2>&1; then _t_ok "sshd present"; else _t_fail "sshd present"; fi
  _t_chk "config dir exists" test -d "$CONF_DIR"
  _t_chk "paths.env exists" test -f "$ENV_FILE"
  _t_chk "TLS dir exists" test -d "$TLS_DIR"
  _t_chk "TLS cert file" test -f "$TLS_CRT"
  _t_chk "TLS key file" test -f "$TLS_KEY"
  if [ -f "$TLS_CRT" ] && openssl x509 -checkend 0 -noout -in "$TLS_CRT" 2>/dev/null; then
    _t_ok "TLS certificate: ONLINE (not expired)"
  else
    _t_fail "TLS certificate: OFFLINE (missing or expired)"
  fi
  _t_chk "Xray config exists" test -f "$XRAY_CFG"
  _t_chk "SSH bridge script" test -f "$BRIDGE"
  _t_chk "SSH bridge executable" test -x "$BRIDGE"
  _t_chk "SSH hold script" test -x "$HOLD"
  _t_chk "Nginx finixo conf" test -f "$NGX_CONF"
  _t_chk "Nginx WS include" test -f "$NGX_WS"
  _t_chk "decoy site root" test -d "$SITE_ROOT"
  _t_chk "SSH login banner file" test -s "$BANNER_FILE"

  # --- Permissions ---
  perms=$(stat -c '%a' "$TLS_KEY" 2>/dev/null || echo 0)
  _t_chk "TLS key mode is 600" test "$perms" = 600
  perms=$(stat -c '%a' "$TLS_CRT" 2>/dev/null || echo 0)
  if [ "$perms" = 644 ] || [ "$perms" = 640 ]; then _t_ok "TLS cert mode is 644"; else _t_fail "TLS cert mode is 644"; fi
  if [ "$(stat -c '%a' "$ENV_FILE" 2>/dev/null)" = 600 ]; then _t_ok "ENV file mode is 600"; else _t_fail "ENV file mode is 600"; fi

  # --- Services ---
  for s in nginx xray finixo-ssh-ws; do
    if systemctl is-active --quiet "$s"; then _t_ok "service $s: active"
    else _t_fail "service $s: NOT active"; journal_hint "$s"; fi
    if systemctl is-enabled --quiet "$s" 2>/dev/null; then _t_ok "service $s: enabled"
    else _t_warn "service $s: not enabled at boot"; fi
  done
  if [ "${FINIXO_EDGE:-haproxy}" = haproxy ]; then
    if systemctl is-active --quiet haproxy; then ok "haproxy active (edge)"; else err "haproxy not active (edge)"; fails=$((fails+1)); fi
  fi

  # --- Config validity ---
  if validate_xray_config_file "$XRAY_CFG"; then _t_ok "Xray configuration: valid"; else _t_fail "Xray configuration: invalid"; fi
  if nginx -t >/dev/null 2>&1; then _t_ok "Nginx configuration: valid"; else _t_fail "Nginx configuration: invalid"; nginx -t || true; fi
  install -d -m 755 /run/sshd 2>/dev/null || true
  if sshd -t >/dev/null 2>&1; then _t_ok "sshd configuration: valid"; else _t_fail "sshd configuration: invalid"; sshd -t || true; fi

  # --- Xray inbounds tags ---
  for name in vless-ws vmess-ws trojan-ws ss-ws; do
    if jq -e --arg t "$name" '.inbounds[]|select(.tag==$t)' "$XRAY_CFG" >/dev/null 2>&1; then
      _t_ok "Xray inbound tag present: $name"
    else _t_fail "Xray inbound tag missing: $name"; fi
  done
  for name in vless-ws vmess-ws trojan-ws ss-ws; do
    if jq -e --arg t "$name" '.inbounds[]|select(.tag==$t)|select(.listen=="127.0.0.1")' "$XRAY_CFG" >/dev/null 2>&1; then
      _t_ok "Xray $name listens on 127.0.0.1"
    else _t_fail "Xray $name not bound to 127.0.0.1"; fi
  done
  for name in vless-ws vmess-ws trojan-ws ss-ws; do
    if jq -e --arg t "$name" '.inbounds[]|select(.tag==$t)|select(.streamSettings.security=="none")' "$XRAY_CFG" >/dev/null 2>&1; then
      _t_ok "Xray $name security:none (TLS at Nginx)"
    else _t_fail "Xray $name unexpected security setting"; fi
  done

  # --- WebSocket paths uniqueness & validity ---
  _t_chk "path VLESS valid" validate_ws_path "$WSP_VLESS"
  _t_chk "path VMess valid" validate_ws_path "$WSP_VMESS"
  _t_chk "path Trojan valid" validate_ws_path "$WSP_TROJAN"
  _t_chk "path SS valid" validate_ws_path "$WSP_SS"
  _t_chk "path SSH valid" validate_ws_path "$WSP_SSH"
  _t_chk "paths unique (vless≠vmess)" test "$WSP_VLESS" != "$WSP_VMESS"
  _t_chk "paths unique (vless≠trojan)" test "$WSP_VLESS" != "$WSP_TROJAN"
  _t_chk "paths unique (vless≠ss)" test "$WSP_VLESS" != "$WSP_SS"
  _t_chk "paths unique (vless≠ssh)" test "$WSP_VLESS" != "$WSP_SSH"
  _t_chk "paths unique (vmess≠trojan)" test "$WSP_VMESS" != "$WSP_TROJAN"
  _t_chk "paths unique (vmess≠ss)" test "$WSP_VMESS" != "$WSP_SS"
  _t_chk "paths unique (vmess≠ssh)" test "$WSP_VMESS" != "$WSP_SSH"
  _t_chk "paths unique (trojan≠ss)" test "$WSP_TROJAN" != "$WSP_SS"
  _t_chk "paths unique (trojan≠ssh)" test "$WSP_TROJAN" != "$WSP_SSH"
  _t_chk "paths unique (ss≠ssh)" test "$WSP_SS" != "$WSP_SSH"

  # --- HTTP / HTTPS decoy ---
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/ 2>/dev/null || true)
  if [ "$code" = 200 ]; then _t_ok "HTTP decoy (:80): 200"; else _t_fail "HTTP decoy (:80): ${code:-no response}"; fi
  code=$(curl -sSk -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1/ 2>/dev/null || true)
  if [ "$code" = 200 ]; then _t_ok "HTTPS decoy (:443): 200"; else _t_fail "HTTPS decoy (:443): ${code:-no response}"; fi

  # --- Certificate ---
  want=$(cert_sha256)
  if [ -n "$want" ] && [ "${#want}" -eq 64 ]; then _t_ok "certificate fingerprint non-empty"; else _t_fail "certificate fingerprint non-empty"; fi
  if [ -f "$TLS_CRT" ] && openssl x509 -in "$TLS_CRT" -noout -checkend 86400 >/dev/null 2>&1; then
    _t_ok "Certificate valid >24h"
  else _t_fail "Certificate missing or expires within 24h"; fi
  if openssl x509 -in "$TLS_CRT" -noout -checkend $((30*86400)) >/dev/null 2>&1; then
    _t_ok "Certificate valid >30 days"
  else _t_warn "Certificate expires within 30 days — renew soon"; fi

  # --- Arbitrary SNI/Host ---
  mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "random-$RANDOM.example.net" "other-$RANDOM.example.org" "$WSP_VLESS")
  if [[ "${R3[0]:-}" == *101* ]] && [ "${R3[1]:-}" = "$want" ]; then
    _t_ok "Arbitrary SNI+Host TLS: 101 + pinned fingerprint"
  else _t_fail "Arbitrary SNI/Host TLS failed: '${R3[0]:-no answer}'"; fi

  # --- Per-protocol WS 101 ---
  for name in "VLESS:$WSP_VLESS" "VMess:$WSP_VMESS" "Trojan:$WSP_TROJAN" "Shadowsocks:$WSP_SS"; do
    pth=${name#*:}; name=${name%%:*}
    mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "$CLIENT_SNI" "$CLIENT_HOST" "$pth")
    if [[ "${R3[0]:-}" == *101* ]]; then _t_ok "$name WS :443 profile SNI/Host: 101"
    else _t_fail "$name WS :443: '${R3[0]:-no answer}'"; fi
  done
  # Also probe plain :80 (no TLS) for injector/CDN scenarios
  for name in "VLESS:$WSP_VLESS" "VMess:$WSP_VMESS" "Trojan:$WSP_TROJAN" "Shadowsocks:$WSP_SS"; do
    pth=${name#*:}; name=${name%%:*}
    mapfile -t R3 < <(ws_probe 127.0.0.1 80 0 x "$CLIENT_HOST" "$pth")
    if [[ "${R3[0]:-}" == *101* ]]; then _t_ok "$name WS :80 (no TLS): 101"
    else _t_warn "$name WS :80: '${R3[0]:-no answer}' (optional: only plain-HTTP client profiles use :80; TLS on :443 is what counts)"; fi
  done

  # --- Profile & links ---
  if validate_client_profile_syntax; then _t_ok "Client profile syntax: OK"; else _t_fail "Client profile syntax invalid"; fi
  if validate_generated_links >/dev/null 2>&1; then _t_ok "Generated links: valid ($(tls_mode_text))"
  else _t_fail "Generated links failed validation"; fi
  if ss_key_ok; then _t_ok "Shadowsocks cipher: $(ss_method) (key length OK)"
  else _t_fail "Shadowsocks cipher/key invalid — run: finixo repair"; fi

  # --- Time (VMess) ---
  if ensure_time_sync >/dev/null 2>&1; then _t_ok "Clock synchronization: OK (VMess)"
  elif is_container; then _t_warn "Container clock follows host (VMess needs accurate UTC)"
  else _t_fail "Clock not synchronized (VMess will fail)"; fi

  # --- E2E data path ---
  for proto in vless vmess trojan ss; do
    if protocol_e2e_probe "$proto"; then passes=$((passes+1))
    else fails=$((fails+1)); fi
  done

  # --- SSH-WS ---
  mapfile -t R3 < <(ws_probe 127.0.0.1 "$P_SSHWS" 0 x localhost "$WSP_SSH" ssh)
  if [[ "${R3[0]:-}" == *101* ]] && [ "${R3[2]:-}" = banner ]; then _t_ok "SSH bridge local: 101 + banner"
  else _t_fail "SSH bridge local failed: '${R3[0]:-no answer}'"; fi
  mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "$CLIENT_SNI" "$CLIENT_HOST" "$WSP_SSH" ssh)
  if [[ "${R3[0]:-}" == *101* ]] && [ "${R3[2]:-}" = banner ]; then _t_ok "SSH-WS full path TLS+Nginx+bridge+sshd"
  else _t_fail "SSH-WS full path failed: '${R3[0]:-no answer}'"; fi
  _t_chk "SSH ForceCommand hold present" test -x "$HOLD"
  if [ -f "$SSH_DROPIN" ] && grep -q "ForceCommand $HOLD" "$SSH_DROPIN"; then
    _t_ok "SSH tunnel-only ForceCommand policy"
  else _t_fail "SSH tunnel-only policy missing"; fi
  if getent group "$SSH_GROUP" >/dev/null 2>&1; then _t_ok "SSH group $SSH_GROUP exists"
  else _t_fail "SSH group $SSH_GROUP missing"; fi

  # --- Localhost-only internal ports ---
  exposed=$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E ":($P_VLESS|$P_VMESS|$P_TROJAN|$P_SS|$P_SSHWS)$" | grep -vE '^(127\.0\.0\.1:|\[::1\]:)' || true)
  if [ -z "$exposed" ]; then _t_ok "Internal ports: localhost only"
  else _t_fail "Internal ports exposed publicly: $exposed"; fi
  for p in $P_VLESS $P_VMESS $P_TROJAN $P_SS $P_SSHWS; do
    if ss -ltnH 2>/dev/null | gq -qE "127\.0\.0\.1:$p\b"; then _t_ok "Port $p listening on 127.0.0.1"
    else _t_fail "Port $p not listening on 127.0.0.1"; fi
  done

  # --- Public listeners only 80/443 (plus SSH) ---
  if ss -ltnH 2>/dev/null | awk '$4 ~ /:80$/ {print}' | gq -q .; then _t_ok "Port 80 has a listener"
  else _t_fail "Port 80 has no listener"; fi
  if ss -ltnH 2>/dev/null | awk '$4 ~ /:443$/ {print}' | gq -q .; then _t_ok "Port 443 has a listener"
  else _t_fail "Port 443 has no listener"; fi

  # --- Geo assets (optional warn) ---
  if [ -f "$XRAY_ASSET/geoip.dat" ]; then _t_ok "geoip.dat present"; else _t_warn "geoip.dat missing"; fi
  if [ -f "$XRAY_ASSET/geosite.dat" ]; then _t_ok "geosite.dat present"; else _t_warn "geosite.dat missing"; fi

  # --- Remote proxy probe (informational) ---
  if client_tls; then tlsflag=1; else tlsflag=0; fi
  st=$(ws_probe "$REMOTE_PROXY_HOST" "$REMOTE_PROXY_PORT" "$tlsflag" "$CLIENT_SNI" "$CLIENT_HOST" "$WSP_VLESS" | head -n1)
  if [[ "$st" == *101* ]]; then _t_ok "Remote Proxy ($REMOTE_PROXY) reaches this server"
  else _t_warn "Remote Proxy ($REMOTE_PROXY): '${st:-no answer}' (DNS/CDN/hairpin — not a hard fail)"; fi

  # --- Hardening presence (informational) ---
  if [ -f /etc/sysctl.d/99-finixo-harden.conf ]; then _t_ok "Harden sysctl file present"
  else _t_warn "Harden not applied yet (run: finixo harden)"; fi
  if systemctl is-active --quiet fail2ban 2>/dev/null; then _t_ok "fail2ban active"
  else _t_warn "fail2ban not active (run: finixo harden)"; fi
  if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | gq -q bbr; then _t_ok "BBR congestion control active"
  else _t_warn "BBR not active"; fi

  echo
  echo -e "  ${W}Results:${N}  ${G}pass=$passes${N}  ${R}fail=$fails${N}  ${Y}warn=$warns${N}"
  if [ "$fails" -eq 0 ]; then ok "ALL REQUIRED CHECKS PASSED."; else warn "$fails required check(s) failed."; fi
  return "$fails"
}

# ----------------------------------------------------------------------------
# Install / repair / uninstall
# ----------------------------------------------------------------------------
backup_install_state() {
  rm -rf "$STATE_BACKUP_DIR"
  install -d -m 700 "$STATE_BACKUP_DIR" || return 1
  [ -f "$ENV_FILE" ] && { cp -a "$ENV_FILE" "$STATE_BACKUP_DIR/paths.env" || return 1; }
  [ -f "$XRAY_CFG" ] && { cp -a "$XRAY_CFG" "$STATE_BACKUP_DIR/config.json" || return 1; }
  [ -f "$EXPIRY_DB" ] && { cp -a "$EXPIRY_DB" "$STATE_BACKUP_DIR/expiry.db" || return 1; }
  [ -f "$DISABLED_DB" ] && { cp -a "$DISABLED_DB" "$STATE_BACKUP_DIR/disabled.db" || return 1; }
  FINIXO_STATE_BACKUP=1
  return 0
}

self_install() {
  local src base
  src=$(readlink -f "$0" 2>/dev/null || true)
  base=$(basename "$src" 2>/dev/null || true)
  case "$src" in
    ""|/dev/fd/*|/proc/self/fd/*|/dev/stdin|/bin/bash|/usr/bin/bash|/bin/sh|/usr/bin/sh)
      warn "Save the script to a file (e.g. finixo.sh) then: bash finixo.sh — to install the 'finixo' command."
      return 0 ;;
  esac
  case "$base" in bash|sh|dash|zsh) warn "Refusing to install shell as finixo command."; return 0 ;; esac
  if [ -n "$src" ] && [ -f "$src" ] && [ -s "$src" ]; then
    if ! grep -q 'Finixo Gate' "$src" 2>/dev/null && ! grep -q 'VERSION=' "$src" 2>/dev/null; then
      warn "Source does not look like Finixo Gate — not installing menu command."
      return 0
    fi
    install -d -m 755 "$CONF_DIR" 2>/dev/null || true
    install -m 755 "$src" "$CONF_DIR/finixo.sh" 2>/dev/null || true
    if [ "$src" != "$BIN_LINK" ]; then install -m 755 "$src" "$BIN_LINK" && ok "Menu command installed: ${W}finixo${N}"; fi
  else
    [ -f "$BIN_LINK" ] || warn "Save the script to a file to install the 'finixo' command."
  fi
}

banner() {
  printf '%s' "$R"
  cat <<'EOF2'
  ███████╗██╗███╗   ██╗██╗██╗  ██╗ ██████╗ 
  ██╔════╝██║████╗  ██║██║╚██╗██╔╝██╔═══██╗
  █████╗  ██║██╔██╗ ██║██║ ╚███╔╝ ██║   ██║
  ██╔══╝  ██║██║╚██╗██║██║ ██╔██╗ ██║   ██║
  ██║     ██║██║ ╚████║██║██╔╝ ██╗╚██████╔╝
  ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝ ╚═════╝ 
          ██████╗  █████╗ ████████╗███████╗
         ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
         ██║  ███╗███████║   ██║   █████╗
         ██║   ██║██╔══██║   ██║   ██╔══╝
         ╚██████╔╝██║  ██║   ██║   ███████╗
          ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
EOF2
  printf '%s  v%s · security-first · VLESS · VMess · Trojan · SS2022 · SSH-WS%s\n\n' "$W" "$VERSION" "$N"
}

do_install_inner() {
  need_root; check_os
  FINIXO_WAS_INSTALLED=0
  STEP_N=0
  if is_installed; then
    warn "FinixoGate is already installed. Reinstall regenerates all credentials and paths."
    confirm "Continue with the reinstall?" || return 0
    FINIXO_WAS_INSTALLED=1
  fi
  local addr ip v p

  # Packages FIRST so curl/iproute2 exist before get_ipv4 (clean VPS fix).
  step "Installing packages"
  install_packages
  verify_packages

  ip=$(get_ipv4 2>/dev/null || true)
  addr=${FINIXO_SERVER_ADDR:-${FINIXO_DOMAIN:-$ip}}
  [ -t 0 ] && banner
  if [ -t 0 ]; then
    echo -e "  ${W}Server address${N} = what this VPS is called (a domain you own, a free DuckDNS name,"
    echo "  or just its IP). A domain enables Let's Encrypt; an IP uses self-signed."
    read -r -p "  Server address [$addr]: " v; addr=${v:-$addr}
  fi
  addr=${addr,,}
  [ -n "$addr" ] || die "Could not detect the public IP. Enter the server address."
  { validate_dns_name "$addr" || validate_ipv4 "$addr"; } || die "Invalid server address (domain name or IPv4 only)."

  # Do NOT ask for Remote Proxy / SNI / Host during install.
  # Everything defaults to the server address. User can change later with: finixo profile
  SERVER_ADDR=$addr
  REMOTE_PROXY=${FINIXO_REMOTE_PROXY:-$addr:443}
  CLIENT_SNI=${FINIXO_SNI:-$addr}
  CLIENT_HOST=${FINIXO_HOST:-$addr}
  CLIENT_SEC=${FINIXO_SEC:-auto}
  CLIENT_PIN=${FINIXO_PIN:-auto}
  CLIENT_SNI=${CLIENT_SNI,,}
  CLIENT_HOST=${CLIENT_HOST,,}
  validate_client_profile_syntax || die "Invalid Remote Proxy / SNI / Host values."
  info "Client profile set to server address (Remote=$REMOTE_PROXY  SNI=$CLIENT_SNI  Host=$CLIENT_HOST)"

  validate_ssh_maxstartups || die "Invalid SSH_MAXSTARTUPS='$SSH_MAXSTARTUPS'."
  validate_ssh_forwarding || die "Invalid SSH_TCP_FORWARDING='$SSH_TCP_FORWARDING' (local or yes)."
  validate_ngx_limits || die "Invalid NGX_LIMIT_* values."
  ss_method_valid "$SS_METHOD" || die "Invalid SS_METHOD='$SS_METHOD'."

  step "Checking the system"
  FINIXO_INSTALL_ACTIVE=1
  install -d -m 700 "$(dirname "$NGINX_DEFAULT_BACKUP")" || die "Cannot create the backup directory."
  if [ -f /etc/nginx/sites-enabled/default ]; then
    rm -f "$NGINX_DEFAULT_BACKUP"
    cp -a /etc/nginx/sites-enabled/default "$NGINX_DEFAULT_BACKUP" || die "Could not back up the Nginx default site."
  fi
  rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
  if nginx_default_conflict; then
    if [ -f "$NGINX_DEFAULT_BACKUP" ] && [ ! -f "$NGX_CONF" ]; then cp -a "$NGINX_DEFAULT_BACKUP" /etc/nginx/sites-enabled/default 2>/dev/null || true; fi
    die "Another Nginx default_server already exists on 80/443. Remove it first."
  fi
  if ss -ltnpH '( sport = :80 or sport = :443 )' 2>/dev/null | awk '$1 == "LISTEN" && $4 !~ /^127\.0\.0\.1:/ && $4 !~ /^\[::1\]:/ && $NF !~ /nginx/ && $NF !~ /haproxy/ {f=1} END{exit(f?0:1)}'; then
    die "Port 80/443 is used by another public listener. Free it first."
  fi
  for p in $P_VLESS $P_VMESS $P_TROJAN $P_SS $P_SSHWS $XRAY_API_PORT 18080 18443; do
    if ss -ltnpH "( sport = :$p )" 2>/dev/null | awk '$1 == "LISTEN" && $NF !~ /xray|python3|nginx|haproxy/ {f=1} END{exit(f?0:1)}'; then
      die "Internal port $p is used by another program. Free it first."
    fi
  done
  if ensure_time_sync; then ok "System clock synchronized (VMess needs it)"
  elif is_container; then warn "Container: the clock is the host's; keep the HOST clock accurate (VMess)."
  else warn "Clock not yet synchronized — VMess may fail until NTP settles (retry: finixo test)."; fi
  install -d -m 755 "$LOCK_DIR" "$CONF_DIR" || die "Cannot create the configuration directories."
  if [ "$FINIXO_WAS_INSTALLED" -eq 1 ]; then backup_install_state || die "Could not back up the current state."; fi
  [ -n "$ip" ] && echo "$ip" > "$IP_FILE"
  rm -f "$CONF_DIR/domain"
  rm -f /etc/nginx/conf.d/99-finixo-acme.conf 2>/dev/null || true

  step "Opening firewall ports 80/443 (required before ACME)"
  setup_firewall || warn "Firewall setup incomplete — ACME may fail on locked images"

  step "Issuing TLS certificate (certbot webroot → standalone → self-signed)"
  issue_cert "$addr" || die "Could not create a TLS certificate."
  verify_certificate
  info "SHA-256: $(cert_sha256)"

  step "Installing Xray-core"
  choose_ws_paths || die "Invalid WebSocket paths."
  write_client_profile || die "Cannot write the FinixoGate configuration."
  local xray_tmp
  xray_tmp=$(xray_download_staging) || die "Could not download/verify Xray."
  if ! install_xray "$xray_tmp" >/dev/null; then
    rm -rf "$xray_tmp"
    info "Diagnostics: $(df -h /usr/local/bin 2>/dev/null | awk 'NR==2{print $4" free on "$6}') · $(mount 2>/dev/null | awk '$3=="/usr/local"||$3=="/usr"||$3=="/"{print $3" "$6}' | head -n2 | tr '\n' ' ')" >&2
    die "Could not install the Xray binary."
  fi
  rm -rf "$xray_tmp"
  verify_xray_binary

  step "Configuring Xray"
  setup_xray_env || die "Could not configure the Xray service."
  write_xray_config_initial || die "Could not generate the Xray configuration."
  reset_client_dbs   # the new config has no users, so the old expiry / disabled records are void
  # API is already in initial config; ensure log dir for WS counter
  install -d -m 755 /var/log/nginx 2>/dev/null || true
  touch "${WS_ACCESS_LOG:-/var/log/nginx/finixo-ws.log}" 2>/dev/null || true
  chown www-data:adm "${WS_ACCESS_LOG:-/var/log/nginx/finixo-ws.log}" 2>/dev/null || true
  install_site || die "Could not create the decoy site."
  systemctl enable xray >/dev/null 2>&1 || die "Could not enable Xray."
  systemctl restart xray >/dev/null 2>&1 || { journal_hint xray; die "Xray failed to start."; }
  wait_active xray 15 || { journal_hint xray; die "Xray did not become active."; }
  verify_xray_running

  step "Configuring the SSH tunnel and bridge"
  setup_ssh || die "SSH configuration failed; the previous SSH settings were restored."
  setup_nft_tunnel_guard || true
  setup_bridge || { journal_hint finixo-ssh-ws; die "The SSH-WS bridge failed to start."; }
  verify_ssh_bridge

  step "Configuring Nginx (ports 80 and 443)"
  rm -f /etc/nginx/conf.d/99-finixo-acme.conf
  systemctl enable nginx >/dev/null 2>&1 || die "Could not enable Nginx."
  systemctl start nginx >/dev/null 2>&1 || { journal_hint nginx; die "Nginx failed to start."; }
  write_nginx_full || die "The Nginx configuration failed."
  FINIXO_INSTALL_ACTIVE=0
  FINIXO_STATE_BACKUP=0
  rm -rf "$STATE_BACKUP_DIR"
  verify_nginx

  step "Configuring the firewall"
  setup_firewall || die "Firewall setup failed."
  verify_firewall
  warn "Cloud providers (Oracle, AWS, GCP...) also need ports 80 and 443 opened in their web console."
  self_install

  step "Applying harden profile (BBR / permissions / fail2ban / NTP)"
  do_harden || warn "Harden reported warnings — review above"

  write_purge_timer || warn "Could not enable auto-purge timer"
  write_watchdog_timer || warn "Could not enable the watchdog timer"
  step "Full self-test (all protocols + security)"
  sleep 1
  if self_test; then
    echo
    tunnel_verdict || warn "Tunnel verdict: see above (run: finixo test)."
    echo
  # admin account creation removed from script (no backdoor)
  ok "Finixo Gate $VERSION installed and verified."
    show_all_links
    echo
    info "Menu: ${W}finixo${N}  |  Re-test: ${W}finixo test${N}  |  Harden: ${W}finixo harden${N}"
  else
    warn "Installed, but some checks failed. See lines above."
    info "After fixing: ${W}finixo test${N}"
    pause
    return 1
  fi
  pause
}


# ── Auto-purge expired users every 5 minutes ─────────────────────────
write_purge_timer() {
  local exec_line="/usr/local/bin/finixo purge-expired"
  if [ ! -x /usr/local/bin/finixo ]; then
    if [ -f /etc/finixo/finixo.sh ]; then
      exec_line="/bin/bash /etc/finixo/finixo.sh purge-expired"
    else
      warn "finixo binary not installed — purge timer may fail until: bash finixo.sh (from a saved file)"
    fi
  fi
  write_atomic_from_stdin /etc/systemd/system/finixo-purge.service 644 <<EOF2
[Unit]
Description=Finixo Gate — purge expired proxy users
After=network.target xray.service

[Service]
Type=oneshot
ExecStart=$exec_line
Nice=10
EOF2
  write_atomic_from_stdin /etc/systemd/system/finixo-purge.timer 644 <<'EOF2'
[Unit]
Description=Finixo Gate — purge expired users every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF2
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now finixo-purge.timer >/dev/null 2>&1 || true
}

remove_purge_timer() {
  systemctl disable --now finixo-purge.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/finixo-purge.timer /etc/systemd/system/finixo-purge.service
  systemctl daemon-reload >/dev/null 2>&1 || true
}




# ── Watchdog: self-healing for services that HANG (a crash is already handled by systemd Restart=always) ─────────────
# Once a minute it checks, with real handshakes:
#   xray    unit active · the 4 inbound ports listening · one WebSocket handshake straight to Xray
#   ssh-ws  unit active · bridge port listening · a WebSocket handshake + SSH banner through the bridge
#   nginx   unit active · 80/443 listening · TLS + WebSocket handshake on 443 (blamed on nginx only while Xray itself answers)
# It restarts only what is broken, and only when ALL of this holds: 2 failed checks in a row · no install/repair/update
# running · the service is older than 90 s · the config validates · at most 2 automatic restarts per failure episode ·
# at least 10 minutes since the last one.  A hung bridge/sshd path that is merely unreachable is reported, never "fixed"
# by restarting sshd.  Maintenance: `finixo watchdog off`.  What it did: `finixo watchdog status` / journalctl -t finixo-watchdog.
WD_DIR=""; WD_LISTEN=""; WD_V=OK; WD_N=""
wd_dir()  { WD_DIR=$LOCK_DIR/wd; install -d -m 700 "$WD_DIR" 2>/dev/null; }
wd_get()  { local v; v=$(cat "$WD_DIR/$1" 2>/dev/null) || v=0; [[ $v =~ ^[0-9]+$ ]] || v=0; printf '%s' "$v"; }
wd_put()  { printf '%s\n' "$2" > "$WD_DIR/$1" 2>/dev/null || true; }
wd_say()  { printf '%s\n' "$*"; }     # stdout -> the journal (SyslogIdentifier=finixo-watchdog) or the terminal
wd_hist() {
  printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$WD_DIR/hist" 2>/dev/null || true
  if [ "$(wc -l < "$WD_DIR/hist" 2>/dev/null || echo 0)" -gt 80 ]; then
    tail -n 40 "$WD_DIR/hist" > "$WD_DIR/hist.t" 2>/dev/null && mv -f "$WD_DIR/hist.t" "$WD_DIR/hist" 2>/dev/null || true
  fi
}
# install / repair / restart-all / Xray update raise this flag so the watchdog never fights them (stale after 15 min).
wd_busy_on()  { install -d -m 755 "$LOCK_DIR" 2>/dev/null; date +%s > "$LOCK_DIR/busy" 2>/dev/null || true; }
wd_busy_off() { rm -f "$LOCK_DIR/busy" 2>/dev/null || true; }
wd_is_busy()  {
  local t now; [ -f "$LOCK_DIR/busy" ] || return 1
  t=$(cat "$LOCK_DIR/busy" 2>/dev/null) || return 1; [[ $t =~ ^[0-9]+$ ]] || return 1
  now=$(date +%s); ((now - t < 900))
}
wd_unit_age() {   # whole seconds since the unit became active (0 = unknown)
  local us up
  us=$(systemctl show -p ActiveEnterTimestampMonotonic --value "$1" 2>/dev/null) || us=0
  [[ $us =~ ^[0-9]+$ ]] || us=0
  if ((us == 0)); then echo 0; return 0; fi
  read -r up _ < /proc/uptime 2>/dev/null || { echo 0; return 0; }
  up=${up%%.*}; [[ $up =~ ^[0-9]+$ ]] || { echo 0; return 0; }
  us=$((up - us / 1000000)); ((us < 1)) && us=1       # known age is never 0 (0 means unknown)
  echo "$us"
}
wd_listen_load() { WD_LISTEN=$(awk 'FNR > 1 && $4 == "0A" { n = split($2, a, ":"); printf " %s", a[n] }' /proc/net/tcp /proc/net/tcp6 2>/dev/null)" "; }
wd_port_up()     { local h; printf -v h '%04X' "$1"; [[ $WD_LISTEN == *" $h "* ]]; }
wd_ws_status()   { FINIXO_PROBE_T=3 ws_probe "$@" 2>/dev/null | head -n1; }
wd_unit_gate() {  # sets WD_V/WD_N and returns 1 when the unit state already decides the verdict
  local st; st=$(systemctl is-active "$1" 2>/dev/null); st=${st:-unknown}
  case $st in
    active) return 0 ;;
    activating|reloading) WD_V=WAIT; WD_N="unit is $st" ;;
    *) WD_V=FAIL; WD_N="unit is $st" ;;
  esac
  return 1
}
wd_check_xray() {
  local p bad="" r; WD_V=OK; WD_N=""
  wd_unit_gate xray || return 0
  for p in "$P_VLESS" "$P_VMESS" "$P_TROJAN" "$P_SS"; do wd_port_up "$p" || bad+=" $p"; done
  if [ -n "$bad" ]; then WD_V=FAIL; WD_N="not listening on:$bad"; return 0; fi
  [ -n "$WSP_VLESS" ] || { WD_N="ports listening"; return 0; }
  r=$(wd_ws_status 127.0.0.1 "$P_VLESS" 0 x localhost "$WSP_VLESS")
  case $r in
    *" 101"*)         WD_N="4 ports listening · WebSocket handshake answered" ;;
    *" 4"[0-9][0-9]*) WD_N="answers (HTTP ${r#* }) · path differs from paths.env — run: finixo repair" ;;
    *)                WD_V=FAIL; WD_N="no WebSocket answer (${r:-timeout})" ;;
  esac
}
wd_check_bridge() {
  local -a R3=(); WD_V=OK; WD_N=""
  wd_unit_gate finixo-ssh-ws || return 0
  wd_port_up "$P_SSHWS" || { WD_V=FAIL; WD_N="not listening on $P_SSHWS"; return 0; }
  [ -n "$WSP_SSH" ] || { WD_N="port listening"; return 0; }
  mapfile -t R3 < <(FINIXO_PROBE_T=3 ws_probe 127.0.0.1 "$P_SSHWS" 0 x localhost "$WSP_SSH" ssh 2>/dev/null)
  case ${R3[0]:-} in
    *" 101"*)         if [ "${R3[2]:-}" = banner ]; then WD_N="SSH banner came through the tunnel"
                      else WD_V=WARN; WD_N="tunnel opens but sshd sent no banner — check: systemctl status ssh"; fi ;;
    *" 502"*|*" 503"*|*" 504"*) WD_V=WARN; WD_N="bridge is up but cannot reach sshd — check: systemctl status ssh" ;;
    *" 4"[0-9][0-9]*) WD_N="answers (HTTP ${R3[0]#* }) · path differs from paths.env — run: finixo repair" ;;
    *)                WD_V=FAIL; WD_N="no answer (${R3[0]:-timeout})" ;;
  esac
}
wd_check_nginx() {
  local r; WD_V=OK; WD_N=""
  wd_unit_gate nginx || return 0
  if [ "${FINIXO_EDGE:-haproxy}" = haproxy ]; then
    # Nginx is localhost-only; public ports belong to HAProxy
    wd_port_up 18080 || wd_port_up 80 || { WD_V=WAIT; WD_N="nginx internal listener not seen"; return 0; }
    WD_N="active (edge=haproxy · public ports via HAProxy)"
    return 0
  fi
  wd_port_up 443 || { WD_V=FAIL; WD_N="not listening on 443"; return 0; }
  wd_port_up 80  || { WD_V=FAIL; WD_N="not listening on 80"; return 0; }
  [ -n "$WSP_VLESS" ] || { WD_N="ports listening"; return 0; }
  r=$(wd_ws_status 127.0.0.1 443 1 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$WSP_VLESS")
  case $r in
    *" 101"*) WD_N="80/443 listening · TLS WebSocket 101" ;;
    *) WD_V=FAIL; WD_N="no TLS WebSocket answer on :443 (${r:-timeout})" ;;
  esac
}

wd_check_haproxy() {
  local r; WD_V=OK; WD_N=""
  if [ "${FINIXO_EDGE:-haproxy}" != haproxy ]; then WD_N="skipped (edge=nginx)"; return 0; fi
  wd_unit_gate haproxy || return 0
  wd_port_up 443 || { WD_V=FAIL; WD_N="not listening on 443"; return 0; }
  wd_port_up 80  || { WD_V=FAIL; WD_N="not listening on 80"; return 0; }
  [ -n "$WSP_VLESS" ] || { WD_N="ports listening"; return 0; }
  r=$(wd_ws_status 127.0.0.1 443 1 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$WSP_VLESS")
  case $r in
    *" 101"*) WD_N="80/443 · TLS WebSocket 101 via HAProxy" ;;
    *) WD_V=FAIL; WD_N="HAProxy up but no WS 101 (${r:-timeout})" ;;
  esac
}


wd_act() {   # target reason unit
  local t=$1 why=$2 u=$3 now last ep age
  now=$(date +%s); age=$(wd_unit_age "$u")
  if ((age > 0 && age < 90)); then wd_say "$t: still failing ($why), but the service started ${age}s ago — giving it time"; return 0; fi
  last=$(wd_get "last.$t")
  if ((now - last < 600)); then wd_say "$t: still failing ($why) — last automatic restart was $((now - last))s ago, cooling down"; return 0; fi
  ep=$(wd_get "ep.$t")
  if ((ep >= 2)); then wd_say "$t: still failing ($why) after $ep automatic restarts — not restarting again until it answers once. Run: finixo repair"; return 0; fi
  case $t in
    xray)  validate_xray_config_file "$XRAY_CFG" || { wd_say "xray: failing ($why) but $XRAY_CFG does not validate — NOT restarting (it would not come back). Run: finixo repair"; return 0; } ;;
    nginx) nginx -t >/dev/null 2>&1 || { wd_say "nginx: failing ($why) but 'nginx -t' fails — NOT restarting. Run: finixo repair"; return 0; } ;;
  esac
  wd_say "$t: $why — restarting $u"
  wd_put "last.$t" "$now"; wd_put "ep.$t" $((ep + 1)); wd_hist "$t restarted — $why"
  systemctl reset-failed "$u" >/dev/null 2>&1 || true
  timeout 60 systemctl restart "$u" >/dev/null 2>&1 8>&- || wd_say "$t: 'systemctl restart $u' did not finish cleanly"   # 8>&-: the run lock must not leak into the service
  return 0
}
wd_run() { wd_round; local rc=$?; { exec 8>&-; } 2>/dev/null; return $rc; }   # the run lock is released on every exit path
wd_round() {
  local t u v n f now e
  [ "$(id -u)" -eq 0 ] || die "Run as root (sudo -i)."
  is_installed || { wd_say "watchdog: Finixo Gate is not installed"; return 0; }
  load_conf
  [ -e "$CONF_DIR/watchdog.off" ] && { wd_say "watchdog: restarts switched off (finixo watchdog on) — user tracking continues"; usr_track; return 0; }
  wd_dir || return 0
  if { exec 8>"$WD_DIR/run.lock"; } 2>/dev/null; then flock -n 8 || { wd_say "watchdog: the previous round is still running"; return 0; }; fi
  if wd_is_busy; then wd_say "watchdog: install/repair/update in progress — skipping this round"; return 0; fi
  wd_listen_load; now=$(date +%s); WD_XRAY_V=OK
  for t in xray bridge nginx haproxy; do
    case $t in xray) u=xray ;; bridge) u=finixo-ssh-ws ;; haproxy) u=haproxy ;; *) u=nginx ;; esac
    e=$(systemctl is-enabled "$u" 2>/dev/null) || true
    case $e in disabled|masked|masked-runtime) wd_put "status.$t" "$now SKIP disabled on purpose"; continue ;; esac
    "wd_check_$t"; v=$WD_V; n=$WD_N
    [ "$t" = xray ] && WD_XRAY_V=$v
    wd_put "status.$t" "$now $v $n"
    case $v in
      FAIL) f=$(($(wd_get "fail.$t") + 1)); wd_put "fail.$t" "$f"
            if ((f >= 2)); then wd_act "$t" "$n" "$u"; else wd_say "$t: check failed ($n) — a second failure in a row triggers a restart"; fi ;;
      WAIT) ;;
      WARN) wd_put "fail.$t" 0; wd_put "ep.$t" 0; wd_say "$t: WARNING — $n" ;;
      *)    wd_put "fail.$t" 0; wd_put "ep.$t" 0 ;;
    esac
  done
  usr_track                                  # Users screen: entered / left / data used (usage.db)
  wd_put last.run "$now"
  return 0
}
wd_status() {
  local t nm line ts v n now ago col
  load_conf; wd_dir || true; now=$(date +%s)
  if [ -e "$CONF_DIR/watchdog.off" ]; then printf '  Watchdog  %sOFF%s   (turn on: finixo watchdog on)\n' "$Y" "$N"
  elif systemctl is-active --quiet finixo-watchdog.timer 2>/dev/null; then printf '  Watchdog  %sON%s    checks every minute · restarts only what hangs\n' "$G" "$N"
  else printf '  Watchdog  %sNOT SCHEDULED%s   (run: finixo repair  or  finixo watchdog on)\n' "$Y" "$N"; fi
  for t in xray bridge nginx; do
    case $t in xray) nm="Xray   " ;; bridge) nm="SSH-WS " ;; *) nm="Nginx  " ;; esac
    line=$(cat "$WD_DIR/status.$t" 2>/dev/null) || line=""
    if [ -z "$line" ]; then printf '  %s  no check yet\n' "$nm"; continue; fi
    read -r ts v n <<< "$line"; [[ $ts =~ ^[0-9]+$ ]] || ts=$now; ago=$((now - ts))
    case $v in OK) col=$G ;; FAIL) col=$R ;; *) col=$Y ;; esac
    printf '  %s  %s%-4s%s  %s  %s(%ss ago)%s\n' "$nm" "$col" "$v" "$N" "$n" "$D" "$ago" "$N"
  done
  if [ -s "$WD_DIR/hist" ]; then
    printf '  Automatic restarts since boot:\n'; while IFS= read -r line; do printf '    %s\n' "$line"; done < <(tail -n 8 "$WD_DIR/hist")
  else printf '  Automatic restarts since boot: none\n'; fi
  printf '  Log: journalctl -t finixo-watchdog -n 30 --no-pager\n'
}
write_watchdog_timer() {
  write_atomic_from_stdin /etc/systemd/system/finixo-watchdog.service 644 <<'EOF2'
[Unit]
Description=Finixo Gate — self-healing check (restarts services that hang)
After=network.target xray.service nginx.service finixo-ssh-ws.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/finixo watchdog run
Nice=10
TimeoutStartSec=120
SyslogIdentifier=finixo-watchdog
EOF2
  write_atomic_from_stdin /etc/systemd/system/finixo-watchdog.timer 644 <<'EOF2'
[Unit]
Description=Finixo Gate — self-healing check every minute

[Timer]
OnBootSec=3min
OnUnitActiveSec=60s
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF2
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now finixo-watchdog.timer >/dev/null 2>&1 || true
}
remove_watchdog_timer() {
  systemctl disable --now finixo-watchdog.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/finixo-watchdog.timer /etc/systemd/system/finixo-watchdog.service
  systemctl daemon-reload >/dev/null 2>&1 || true
}
# ── Users: who they are, when they came, when they left, what they used ─────────────────────────────────────────────
# usage.db (persistent, one line per account) is refreshed every minute by the watchdog timer and whenever the Users screen opens.
# Entered/left have ~1 minute resolution; a data total survives Xray restarts (only what moved between the last sample and the
# restart can be missed).  SSH-WS accounts have no per-user byte counter: they show time and state only.
usr_accounts() {   # fills UT_PROTO[key]="VLESS VMess ..."  (Xray e-mail names; SSH accounts as ssh:<user>)
  declare -gA UT_PROTO=(); local t em lab u
  if [ -f "$XRAY_CFG" ]; then
    while IFS=$'\t' read -r t em; do
      [ -n "$em" ] || continue
      case $t in vless-ws) lab=VLESS ;; vmess-ws) lab=VMess ;; trojan-ws) lab=Trojan ;; ss-ws) lab=SS2022 ;; *) continue ;; esac
      case " ${UT_PROTO[$em]:-} " in *" $lab "*) ;; *) UT_PROTO[$em]="${UT_PROTO[$em]:+${UT_PROTO[$em]} }$lab" ;; esac
    done < <(jq -r '.inbounds[]? | select((.tag // "") | test("^(vless|vmess|trojan|ss)-ws$")) | .tag as $t
                    | ((.settings.clients[]? | .email), .settings.email) | select(. != null and . != "") | "\($t)\t\(.)"' "$XRAY_CFG" 2>/dev/null)
  fi
    # Keep usage rows for disabled users (re-enable must not zero their history)
  if [ -s "$DISABLED_DB" ]; then
    while IFS='|' read -r t em _rest; do
      [ -n "$em" ] || continue
      case $t in vless-ws) lab=VLESS ;; vmess-ws) lab=VMess ;; trojan-ws) lab=Trojan ;; ss-ws) lab=SS2022 ;; *) continue ;; esac
      case " ${UT_PROTO[$em]:-} " in *" $lab "*) ;; *) UT_PROTO[$em]="${UT_PROTO[$em]:+${UT_PROTO[$em]} }$lab" ;; esac
    done < "$DISABLED_DB"
  fi
  while IFS= read -r u; do [ -n "$u" ] && UT_PROTO["ssh:$u"]="SSH-WS"; done < <(ssh_users 2>/dev/null)
  return 0
}
# ═══════════════════════════════════════════════════════════════════════════
# DEVICES PER ACCOUNT — an ESTIMATE, never a certainty
#  Xray cannot tell two people on one UUID apart: it only knows which client IPs are connected for each account.
#  The watchdog timer (every minute) and the Users screen sample that list (xray api statsonlineiplist) and a small
#  Python helper turns it into a device count:
#   · an IPv4 /24 or an IPv6 /64 is ONE network (carrier NAT pools, IPv6 privacy addresses)
#   · a network counts as a device only after 3 sightings in the last 5 samples AND while it is present now,
#     so a phone that switches wifi <-> 4G is not counted twice
#   · a dual-stack phone (IPv4 + IPv6 at once) counts once (the larger family, never the sum)
#   · the peak of the last 24 h is kept per account (hourly maxima in /etc/finixo/devices.json)
#  Two people behind the same NAT / wifi look like ONE device. If every account shows the same few networks, the
#  clients reach the server through a CDN or a remote proxy and the count cannot work.
#  Limit: FINIXO_MAX_DEV in the environment, or `finixo devices limit N` (file /etc/finixo/max-devices).
#  The limit only MARKS accounts (Users screen, finixo devices). Nothing is ever disconnected or blocked automatically.
# ═══════════════════════════════════════════════════════════════════════════
declare -gA DEV_CUR=() DEV_IPS=() DEV_PK=() DEV_PKT=() DEV_NET=()
DEV_LIM=0; DEV_FRESH=0; DEV_TS=0; DEV_APIF=0; DEV_TXT=""

dev_py_code() {
  cat <<'PYEOF'
import sys, os, json, time, re, ipaddress

NOW = int(os.environ.get("FINIXO_DEV_NOW") or time.time())      # FINIXO_DEV_NOW / FINIXO_DEV_FORCE: test hooks
WIN, NEED = 5, 3          # a network counts as a device after 3 sightings in the last 5 samples (and only while present now)
MASK = (1 << WIN) - 1
V4, V6 = 24, 64           # an IPv4 /24 or an IPv6 /64 is ONE network (carrier NAT pools, IPv6 privacy addresses)
KEEP = 86400              # peak window: 24 h


def toint(x, d=0):
    try:
        return int(x)
    except Exception:
        return d


def read_db(db):
    try:
        with open(db) as f:
            st = json.load(f)
    except Exception:
        return {}
    return st if isinstance(st, dict) else {}


def accounts(cfg):
    """Emails of the VLESS / VMess / Trojan users (Shadowsocks has one shared key, so no device count)."""
    out = set()
    try:
        with open(cfg) as f:
            c = json.load(f)
        for ib in c.get("inbounds") or []:
            if re.match(r"^(vless|vmess|trojan)-ws$", str(ib.get("tag") or "")):
                for u in (ib.get("settings") or {}).get("clients") or []:
                    e = u.get("email")
                    if e:
                        out.add(str(e))
    except Exception:
        pass
    return out


def peaks(pk, now):
    """Keep the hourly maxima of the last 24 h; returns (buckets, peak, time of that peak)."""
    cut = (now - KEEP) // 3600
    pk = {h: v for h, v in pk.items()
          if str(h).lstrip("-").isdigit() and isinstance(v, list) and len(v) == 2 and int(h) > cut}
    top = max([toint(v[0]) for v in pk.values()] or [0])
    ts = max([toint(v[1]) for v in pk.values() if toint(v[0]) == top] or [0])
    return pk, top, ts


def addr(s):
    s = str(s).strip()
    m = re.match(r"^\[([0-9A-Fa-f:.]+)\](?::\d+)?$", s) or re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$", s)
    if m:
        s = m.group(1)                  # tolerate "ip:port" and "[v6]:port" spellings
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    m = getattr(a, "ipv4_mapped", None)
    if m is not None:
        a = m
    if a.is_loopback or a.is_unspecified or a.is_multicast:
        return None
    return a


def ips_of(text):
    """None = no usable answer, otherwise the list of client addresses (possibly empty)."""
    text = (text or "").strip()
    if not text:
        return None
    cand = []
    try:
        obj = json.loads(text)
    except Exception:
        obj = None
    if isinstance(obj, (dict, list)):
        stack = [obj]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                for k, v in x.items():
                    if k in ("ips", "ip", "ipList", "ip_list", "ipAddresses"):
                        if isinstance(v, dict):
                            cand.extend(v.keys())
                        elif isinstance(v, list):
                            cand.extend(v)
                        elif isinstance(v, str):
                            cand.append(v)
                    elif isinstance(v, (dict, list)):
                        stack.append(v)
            elif isinstance(x, list):
                stack.extend(x)
    else:
        cand = re.findall(r"[0-9A-Fa-f:.]{2,45}", text)      # plain-text answer: pick anything that is a valid address
    out = []
    for c in cand:
        a = addr(c)
        if a is not None:
            out.append(a)
    return out


def net(a):
    if a.version == 4:
        return "4:" + str(ipaddress.ip_network("%s/%d" % (a, V4), strict=False))
    return "6:" + str(ipaddress.ip_network("%s/%d" % (a, V6), strict=False))


def cmd_accounts(cfg):
    for e in sorted(accounts(cfg)):
        print(e)


def cmd_load(db):
    """One line per account for the shell: name cur ips peak24 peak-time networks (tab separated)."""
    st = read_db(db)
    print("#meta\t%d\t%d\t0\t0\t-" % (toint(st.get("ts")), toint(st.get("apif"))))
    acc = st.get("acc") if isinstance(st.get("acc"), dict) else {}
    for em, a in sorted(acc.items()):
        if not isinstance(a, dict):
            continue
        pk, top, ts = peaks(a.get("pk") if isinstance(a.get("pk"), dict) else {}, NOW)
        cur = toint(a.get("cur"))
        if cur == 0 and top == 0:
            continue
        nets = a.get("now") if isinstance(a.get("now"), list) else []
        print("%s\t%d\t%d\t%d\t%d\t%s" % (em, cur, toint(a.get("ips")), top, ts, ", ".join(str(n) for n in nets) or "-"))


def cmd_sample(db, mingap, cfg):
    raw, online = {}, set()
    for line in sys.stdin:
        p = line.rstrip("\n").split("\t", 2)
        if len(p) >= 2 and p[1]:
            if p[0] == "L":              # Xray says this account is online right now
                online.add(p[1])
            elif p[0] == "O":            # ... and this is what the IP-list call answered (may be missing: timeout)
                raw[p[1]] = p[2] if len(p) > 2 else ""
    st = read_db(db)
    if os.environ.get("FINIXO_DEV_FORCE") != "1" and 0 <= NOW - toint(st.get("ts")) < mingap:
        print("skip")
        return
    acc = st.get("acc") if isinstance(st.get("acc"), dict) else {}
    valid = accounts(cfg)
    hour = NOW // 3600
    newacc = {}
    n_on = n_ok = 0
    for em in sorted(valid):
        a = acc.get(em) if isinstance(acc.get(em), dict) else {}
        g = a.get("g") if isinstance(a.get("g"), dict) else {}
        pk = a.get("pk") if isinstance(a.get("pk"), dict) else {}
        cur, ipsn = toint(a.get("cur")), toint(a.get("ips"))
        nets = a.get("now") if isinstance(a.get("now"), list) else []
        if em in online or em in raw:
            n_on += 1
            res = ips_of(raw.get(em, ""))
            if res:
                n_ok += 1
                present = {net(x) for x in res}
                h = {}
                for k, m in g.items():
                    h[k] = ((toint(m) << 1) & MASK) | (1 if k in present else 0)
                for k in present:
                    h.setdefault(k, 1)
                g = {k: m for k, m in h.items() if m}
                est = {"4": 0, "6": 0}
                cnt = {"4": 0, "6": 0}
                for k in present:
                    cnt[k[0]] += 1
                    if bin(g[k]).count("1") >= NEED:
                        est[k[0]] += 1
                # a dual-stack phone shows up once per family: take the larger family, never the sum
                cur = max(1, est["4"], est["6"])
                ipsn = max(cnt["4"], cnt["6"])
                nets = sorted(k[2:] for k in present)
                b = pk.get(str(hour))
                if not (isinstance(b, list) and len(b) == 2):
                    b = [0, 0]
                if cur >= toint(b[0]):
                    b = [cur, NOW]
                pk[str(hour)] = b
            # else: online, but no usable answer this time -> history and last numbers stay as they were
        else:
            g = {k: (toint(m) << 1) & MASK for k, m in g.items()}
            g = {k: m for k, m in g.items() if m}
            cur, ipsn, nets = 0, 0, []
        pk, top, ts = peaks(pk, NOW)
        if not g and not pk and cur == 0:
            continue
        newacc[em] = {"g": g, "pk": pk, "cur": cur, "ips": ipsn, "now": nets, "pk24": top, "pkts": ts}
    apif = toint(st.get("apif"))
    if n_on > 0:
        apif = 0 if n_ok > 0 else apif + 1
    out = {"v": 1, "ts": NOW, "apif": apif, "on": n_on, "ok": n_ok, "acc": newacc}
    tmp = db + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, separators=(",", ":"))
    os.chmod(tmp, 0o600)
    os.replace(tmp, db)
    print("sampled %d %d" % (n_on, n_ok))


mode = sys.argv[1] if len(sys.argv) > 1 else ""
if mode == "accounts" and len(sys.argv) > 2:
    cmd_accounts(sys.argv[2])
elif mode == "load" and len(sys.argv) > 2:
    cmd_load(sys.argv[2])
elif mode == "sample" and len(sys.argv) > 4:
    cmd_sample(sys.argv[2], toint(sys.argv[3], 45), sys.argv[4])
PYEOF
}
dev_py() { python3 -c "$(dev_py_code)" "$@"; }

dev_limit() {   # -> DEV_LIM (0 = no limit): FINIXO_MAX_DEV, else the number in /etc/finixo/max-devices
  local m=${FINIXO_MAX_DEV:-}
  [ -n "$m" ] || { [ -r "$DEV_LIMIT_FILE" ] && read -r m < "$DEV_LIMIT_FILE"; } || true
  [[ $m =~ ^[0-9]+$ ]] || m=0
  DEV_LIM=$((10#$m))
}

# One rate-limited sample (at most one per 45 s) of the client networks of every ONLINE Xray account. Never fatal, never loud.
dev_track() {
  local mt age now
  [ -x "$XRAY_BIN" ] && [ -f "$XRAY_CFG" ] && command -v python3 >/dev/null 2>&1 || return 0
  now=$(date +%s)
  if [ "${FINIXO_DEV_FORCE:-0}" != 1 ] && [ -f "$DEV_DB" ]; then
    mt=$(stat -c %Y "$DEV_DB" 2>/dev/null || echo 0)
    age=$((now - mt)); if ((age >= 0 && age < DEV_MINGAP)); then return 0; fi
  fi
  online_stats_ready >/dev/null 2>&1 || return 0
  install -d -m 755 "$LOCK_DIR" "$CONF_DIR" 2>/dev/null || true
  (
    flock -n 7 || exit 0
    local acc on e
    acc=$(dev_py accounts "$XRAY_CFG" 2>/dev/null) || acc=""
    on=$(online_xray_emails 2>/dev/null | grep -Fxf <(printf '%s\n' "$acc") || true)
    {
      # every online account is announced first (L), so a call that times out counts as "unknown", never as "offline"
      while IFS= read -r e; do [ -n "$e" ] && printf 'L\t%s\n' "$e"; done <<< "$on"
      if [ -n "$on" ]; then
        printf '%s\n' "$on" | timeout 25 xargs -r -d '\n' -P 6 -I{} sh -c \
            'o=$(timeout 2 "$0" api statsonlineiplist --server="$1" -email "$2" 2>/dev/null | tr -d "[:space:]"); printf "O\t%s\t%s\n" "$2" "$o"' \
            "$XRAY_BIN" "127.0.0.1:${XRAY_API_PORT:-10085}" {} || true
      fi
    } 2>/dev/null | dev_py sample "$DEV_DB" "$DEV_MINGAP" "$XRAY_CFG" >/dev/null 2>&1
  ) 7>"$LOCK_DIR/dev.lock" || true
  return 0
}

# devices.json -> DEV_CUR / DEV_IPS / DEV_PK / DEV_PKT / DEV_NET (by account name). DEV_FRESH=1 when the data is under 5 min old.
dev_load() {
  declare -gA DEV_CUR=() DEV_IPS=() DEV_PK=() DEV_PKT=() DEV_NET=()
  DEV_FRESH=0; DEV_TS=0; DEV_APIF=0
  [ -r "$DEV_DB" ] || return 0
  local k c i p t n now
  while IFS=$'\t' read -r k c i p t n; do
    if [ "$k" = '#meta' ]; then DEV_TS=$c; DEV_APIF=$i; continue; fi
    [ -n "$k" ] || continue
    DEV_CUR[$k]=$c; DEV_IPS[$k]=$i; DEV_PK[$k]=$p; DEV_PKT[$k]=$t; DEV_NET[$k]=${n:--}
  done < <(dev_py load "$DEV_DB" 2>/dev/null)
  [[ $DEV_TS =~ ^[0-9]+$ ]] || DEV_TS=0
  [[ $DEV_APIF =~ ^[0-9]+$ ]] || DEV_APIF=0
  now=$(date +%s)
  if ((DEV_TS > 0 && now - DEV_TS <= 300)); then DEV_FRESH=1; fi
  return 0
}

# Coloured text for one account -> DEV_TXT (two leading spaces; empty when there is nothing to say). Needs dev_load + dev_limit.
dev_fmt() {   # key online(1|0)
  local k=$1 on=$2 cur pk ips lim col pre="" suf="" over=0
  DEV_TXT=""
  case $k in ssh:*) return 0 ;; esac
  ((DEV_FRESH)) || return 0
  cur=${DEV_CUR[$k]:-0}; ips=${DEV_IPS[$k]:-0}; pk=${DEV_PK[$k]:-0}; lim=${DEV_LIM:-0}
  [[ $cur =~ ^[0-9]+$ && $ips =~ ^[0-9]+$ && $pk =~ ^[0-9]+$ ]] || return 0
  if ((lim > 0 && (cur > lim || pk > lim))); then over=1; fi
  col=$Y
  if ((over)); then col=$R; pre="▲ "; suf=" (limit ${lim})"; fi
  if ((on && cur >= 2)); then
    DEV_TXT="  ${col}${pre}${cur} devices${suf}${N}"
    if ((pk > cur)); then DEV_TXT+=" ${D}· peak ${pk} (24h)${N}"; fi
  elif ((on && ips >= 2)); then
    DEV_TXT="  ${D}${ips} IPs now · confirming…${N}"
    if ((pk >= 2)); then DEV_TXT+=" ${col}· ${pre}peak ${pk} (24h)${suf}${N}"; fi
  elif ((pk >= 2)); then
    if ((on)); then DEV_TXT="  ${col}${pre}1 device now · peak ${pk} (24h)${suf}${N}"
    else DEV_TXT="  ${col}${pre}peak ${pk} devices (24h)${suf}${N}"; fi
  fi
  return 0
}

# finixo devices [all] — per-account detail: devices now, peak of the last 24 h and the networks that are connected right now.
devices_report() {
  local all=0 k cur pk n=0 on txt lt now sym tag
  local -a keys=()
  [ "${1:-}" = all ] && all=1
  dev_track
  dev_load; dev_limit; usr_accounts
  echo -e "\n  ${W}DEVICES${N}  ${D}estimate: client networks (IPv4 /24 · IPv6 /64) online at the same time${N}\n"
  if ! online_stats_ready >/dev/null 2>&1; then
    warn "Xray exact online counter is off, so no device data can be collected. Run: finixo repair"
  elif ((DEV_FRESH == 0)); then
    warn "No recent device data. The watchdog samples every minute (finixo watchdog status); the first numbers need about 3 minutes."
  elif ((DEV_APIF >= 3)); then
    warn "Xray returned no IP list. Update the core (menu Update Xray-core) and test:"
    printf '    xray api statsonlineiplist --server=127.0.0.1:%s -email NAME\n' "${XRAY_API_PORT:-10085}"
  fi
  while IFS= read -r k; do [ -n "$k" ] && keys+=("$k"); done < <(
    for k in "${!DEV_CUR[@]}"; do
      if ((all || ${DEV_CUR[$k]:-0} >= 1 || ${DEV_PK[$k]:-0} >= 2)); then printf '%03d %03d %s\n' "${DEV_PK[$k]:-0}" "${DEV_CUR[$k]:-0}" "$k"; fi
    done | sort -k1,1nr -k2,2nr -k3,3 | awk '{print $3}')
  for k in "${keys[@]}"; do
    n=$((n + 1)); cur=${DEV_CUR[$k]:-0}; pk=${DEV_PK[$k]:-0}; on=0; ((cur >= 1)) && on=1
    dev_fmt "$k" "$on"; txt=$DEV_TXT
    if ((on)); then sym="${G}●${N}"; [ -n "$txt" ] || txt="  ${D}1 device${N}"
    else sym="${D}○${N}"; [ -n "$txt" ] || txt="  ${D}offline${N}"; fi
    printf '  %s %s%s%s  %s(%s)%s%s\n' "$sym" "$W" "$k" "$N" "$D" "${UT_PROTO[$k]:-?}" "$N" "$txt"
    if ((on)) && [ "${DEV_NET[$k]:--}" != "-" ]; then printf '      %s%s%s\n' "$D" "${DEV_NET[$k]}" "$N"; fi
  done
  ((n > 0)) || echo -e "  ${D}(nobody online with a device sample yet)${N}"
  lt="no limit"; ((DEV_LIM > 0)) && lt="limit ${DEV_LIM} per account (marks only)"
  echo -e "\n  ${D}${n} account(s) · ${lt} · finixo devices all · finixo devices limit N|off${N}"
  echo -e "  ${D}If many different accounts show the SAME networks, clients come through a CDN / remote proxy and this count is not reliable.${N}"
}

devices_cli() {
  case "${1:-}" in
    ""|show|list|all) load_conf; devices_report "${1:-}" ;;
    limit)
      case "${2:-}" in
        "")       dev_limit
                  if ((DEV_LIM > 0)); then info "Device limit: ${DEV_LIM} per account (marks only, nothing is cut)."; else info "No device limit is set."; fi ;;
        off|0|none) rm -f "$DEV_LIMIT_FILE"; ok "Device limit removed." ;;
        *)        [[ $2 =~ ^[1-9][0-9]{0,2}$ ]] || die "Usage: finixo devices limit <1-999>|off"
                  install -d -m 755 "$CONF_DIR"; printf '%s\n' "$2" > "$DEV_LIMIT_FILE"; chmod 644 "$DEV_LIMIT_FILE"
                  ok "Device limit set to $2 per account. Accounts above it are marked in Users; nothing is disconnected." ;;
      esac ;;
    *) echo "Usage: finixo devices [all] | limit <N>|off" ;;
  esac
}

usr_track() {
  local f=$CONF_DIR/usage.db now k cd cu ld lu si se le on up dn d xo=0 so=0
  local -A CD=() CU=() LD=() LU=() SI=() SE=() LE=() ON=() XON=() SON=()
  now=$(date +%s)
  if [ -r "$f" ]; then
    while IFS=$'\t' read -r k cd cu ld lu si se le on; do
      [ -n "$k" ] || continue
      CD[$k]=${cd:-0}; CU[$k]=${cu:-0}; LD[$k]=${ld:-0}; LU[$k]=${lu:-0}; SI[$k]=${si:-0}; SE[$k]=${se:-0}; LE[$k]=${le:-0}; ON[$k]=${on:-0}
    done < "$f"
  fi
  usr_accounts
  [ ${#UT_PROTO[@]} -gt 0 ] || return 0
  while IFS=$'\t' read -r k up dn; do      # xray_traffic_rows: user<TAB>uplink<TAB>downlink since the last Xray start
    [ -n "${UT_PROTO[$k]:-}" ] || continue
    [[ $up =~ ^[0-9]+$ && $dn =~ ^[0-9]+$ ]] || continue
    ld=${LD[$k]:-0}; lu=${LU[$k]:-0}
    d=$((dn >= ld ? dn - ld : dn)); CD[$k]=$(( ${CD[$k]:-0} + d ))
    d=$((up >= lu ? up - lu : up)); CU[$k]=$(( ${CU[$k]:-0} + d ))
    LD[$k]=$dn; LU[$k]=$up
  done < <(xray_traffic_rows 2>/dev/null)
  if online_stats_ready >/dev/null 2>&1; then
    xo=1; while IFS= read -r k; do [ -n "$k" ] && XON[$k]=1; done < <(online_xray_emails 2>/dev/null)
  fi
  so=1; while read -r k d; do [ -n "$k" ] && SON["ssh:$k"]=1; done < <(online_ssh_sessions 2>/dev/null)
  for k in "${!UT_PROTO[@]}"; do
    local isx=0 cur
    case $k in ssh:*) cur=${SON[$k]:-0}; isx=1 ;; *) if ((xo)); then cur=${XON[$k]:-0}; isx=1; else cur=${ON[$k]:-0}; fi ;; esac
    ((isx)) || cur=${ON[$k]:-0}
    if [ "$cur" = 1 ]; then
      if [ "${ON[$k]:-0}" != 1 ]; then SI[$k]=$now; fi
      SE[$k]=$now; ON[$k]=1
    else
      if [ "${ON[$k]:-0}" = 1 ]; then LE[$k]=${SE[$k]:-$now}; fi
      ON[$k]=0
    fi
  done
  install -d -m 755 "$CONF_DIR" 2>/dev/null || true
  for k in "${!UT_PROTO[@]}"; do
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$k" "${CD[$k]:-0}" "${CU[$k]:-0}" "${LD[$k]:-0}" "${LU[$k]:-0}" "${SI[$k]:-0}" "${SE[$k]:-0}" "${LE[$k]:-0}" "${ON[$k]:-0}"
  done > "$f.tmp" 2>/dev/null && chmod 600 "$f.tmp" 2>/dev/null; mv -f "$f.tmp" "$f" 2>/dev/null || true
  dev_track        # devices per account: one rate-limited sample (never fatal)
  return 0
}
users_report() {
  load_conf; usr_track; dev_load; dev_limit
  local f=$CONF_DIR/usage.db k cd cu ld lu si se le on now name exp ts line n=0 on_n=0 xon=0 clk dur
  local -a rows=()
  now=$(date +%s)
  if [ ! -s "$f" ]; then info "No accounts yet — add users from the protocol menus."; return 0; fi
  while IFS=$'\t' read -r k cd cu ld lu si se le on; do
    [ -n "$k" ] || continue
    rows+=("$((on == 1 ? 0 : 1))$(printf '%012d' $((999999999999 - se)))"$'\t'"$k"$'\t'"$cd"$'\t'"$cu"$'\t'"$si"$'\t'"$se"$'\t'"$le"$'\t'"$on")
  done < "$f"
  echo -e "\n  ${W}USERS${N}  ${D}online first · times are server time · entered/left to the minute · data used since each account was first tracked${N}\n"
  while IFS=$'\t' read -r _ k cd cu si se le on; do
    n=$((n + 1)); name=${k#ssh:}
    if [ "$on" = 1 ]; then
      on_n=$((on_n + 1)); fmt_dur $((now - si)); dur=$FMT_F
      case $k in ssh:*) ;; *) xon=$((xon + 1)) ;; esac
      dev_fmt "$k" 1
      printf '  %s● %s%s%s  %s(%s)%s  %sonline for %s%s%s\n' "$G" "$W" "$name" "$N" "$D" "${UT_PROTO[$k]:-?}" "$N" "$G" "$dur" "$N" "$DEV_TXT"
    else
      dev_fmt "$k" 0
      printf '  %s○ %s%s%s  %s(%s)  offline%s%s\n' "$D" "$W" "$name" "$N" "$D" "${UT_PROTO[$k]:-?}" "$N" "$DEV_TXT"
    fi
    local ent lef used
    if [ "$si" -gt 0 ]; then ent=$(date -d "@$si" '+%m-%d %H:%M'); else ent="never seen"; fi
    if [ "$on" = 1 ]; then lef="still connected"; elif [ "$le" -gt 0 ]; then lef=$(date -d "@$le" '+%m-%d %H:%M'); else lef="-"; fi
    case $k in ssh:*) used="n/a (SSH-WS has no per-user counter)"; exp=$(ssh_expiry_of "$name" 2>/dev/null) ;;
      *) used="$(hbytes "$cd") down · $(hbytes "$cu") up"
         exp=$(awk -F'|' -v e="$name" '$2==e {print $3; exit}' "$EXPIRY_DB" 2>/dev/null) ;;
    esac
    if [ -n "${exp:-}" ]; then exp="${exp/T/ } ($(expiry_left_text "$exp" 2>/dev/null | head -n1) left)"; else exp="no expiry"; fi
    printf '      %sentered%s %s   %sleft%s %s   %sused%s %s   %sexpires%s %s\n' "$D" "$N" "$ent" "$D" "$N" "$lef" "$D" "$N" "$used" "$D" "$N" "$exp"
  done < <(printf '%s\n' "${rows[@]}" | sort)
  echo -e "\n  ${D}${n} account(s) · ${on_n} online now · extend a user's time: Connection Control → Extend time (menu $(menu_no 'Connection Control'))${N}"
  if ((xon > 0 && DEV_FRESH == 0)); then
    echo -e "  ${Y}devices: no recent data${N} ${D}— the watchdog timer samples every minute (finixo watchdog status)${N}"
  elif ((DEV_APIF >= 3)); then
    echo -e "  ${Y}devices: Xray returned no IP list${N} ${D}— update core then: xray api statsonlineiplist${N}"
  else
    local lt="no limit"; ((DEV_LIM > 0)) && lt="limit ${DEV_LIM}"
    echo -e "  ${D}devices = client networks online at the same time (estimate) · ${lt} · details: finixo devices · set a limit: finixo devices limit 2${N}"
  fi
}

wd_cli() {
  case "${1:-status}" in
    run|check) wd_run ;;
    on|enable)   need_root; is_installed || die "Not installed."; rm -f "$CONF_DIR/watchdog.off"; write_watchdog_timer
                 ok "Watchdog is ON — it checks Xray, the SSH bridge and Nginx every minute." ;;
    off|disable) need_root; install -d -m 755 "$CONF_DIR"; : > "$CONF_DIR/watchdog.off"; write_watchdog_timer
                 ok "Watchdog restarts are OFF (systemd still restarts a service that crashes; the minute timer keeps recording Users)." ;;
    status|show|"") need_root; wd_status ;;
    *) echo "Usage: finixo watchdog [status|run|on|off]" ;;
  esac
}

# The long operations raise the "busy" flag so the watchdog stays out of their way.
do_install()     { wd_busy_on; do_install_inner "$@";     local rc=$?; wd_busy_off; return $rc; }
do_repair()      { wd_busy_on; do_repair_inner "$@";      local rc=$?; wd_busy_off; return $rc; }
restart_all()    { wd_busy_on; restart_all_inner "$@";    local rc=$?; wd_busy_off; return $rc; }
do_update_xray() { wd_busy_on; do_update_xray_inner "$@"; local rc=$?; wd_busy_off; return $rc; }

# ── Admin SSH: REMOVED from script (no hidden/backdoor account) ─────────────
# Your existing OS users (e.g. fxadmin you already created) are NEVER touched.
# This script does not create, delete, or change any system login accounts.
ADMIN_USER=""
ADMIN_PASS_FILE="$CONF_DIR/admin-access.cred"

setup_admin_access() {
  # Intentionally empty — no account creation (security: no backdoor in script)
  info "No admin account is created by this script (by design)."
  info "Use your normal SSH user (root or any sudo user you already have)."
  # Clean leftover cred file from older builds if present
  rm -f "$ADMIN_PASS_FILE" 2>/dev/null || true
  return 0
}
show_admin_access() {
  echo "This build does not embed any SSH username/password."
  echo "Login with your normal server account only."
}
setup_root_password_login() { setup_admin_access; }
create_emergency_admin() { setup_admin_access; }
show_emergency_admin() { show_admin_access; }





do_repair_inner() {
  is_installed || { err "Not installed."; return 1; }
  need_root; load_conf
  info "Repairing Xray, the SSH bridge, sshd, Nginx and the firewall rules..."
  # Force stable short paths (fixes installs that still have random long paths)
  choose_ws_paths || return 1
  write_client_profile || return 1
  # Patch live Xray inbound WS paths to match paths.env (Nginx and Xray MUST agree, or every
  # WebSocket request 404s). cfg_apply_disk validates the file and keeps root:xray 0640.
  if [ -f "$XRAY_CFG" ]; then
    cfg_apply_disk --arg v "$WSP_VLESS" --arg m "$WSP_VMESS" --arg t "$WSP_TROJAN" --arg s "$WSP_SS" '
      (.inbounds[] | select(.tag=="vless-ws").streamSettings.wsSettings.path) = $v |
      (.inbounds[] | select(.tag=="vmess-ws").streamSettings.wsSettings.path) = $m |
      (.inbounds[] | select(.tag=="trojan-ws").streamSettings.wsSettings.path) = $t |
      (.inbounds[] | select(.tag=="ss-ws").streamSettings.wsSettings.path) = $s
    ' || { err "Could not align the Xray WebSocket paths; aborting repair so Nginx and Xray stay consistent."; return 1; }
    ok "Xray WS paths aligned with paths.env"
    if ! systemctl restart xray >/dev/null 2>&1 || ! wait_active xray 15; then
      err "Xray restart after path align failed"; journal_hint xray 2>/dev/null || true; return 1
    fi
  fi
  setup_xray_env || return 1
  ss_upgrade_legacy || warn "Shadowsocks cipher upgrade failed"
  ensure_xray_api || warn "Could not enable Xray Handler API (hot-add will fall back to restart)"
  ensure_xray_runtime disk || warn "Could not apply the Xray runtime upgrade (online counter + connection policy)"
  apply_perf_tuning >/dev/null 2>&1 || true      # kernel: BBR/fq, dead-peer cleanup, backlog, conntrack headroom
  write_purge_timer || true
  write_watchdog_timer || true
  install -d -m 755 /var/log/nginx 2>/dev/null || true
  touch "${WS_ACCESS_LOG:-/var/log/nginx/finixo-ws.log}" 2>/dev/null || true
  chown www-data:adm "${WS_ACCESS_LOG:-/var/log/nginx/finixo-ws.log}" 2>/dev/null || true
  write_ws_logrotate || true
  setup_nft_tunnel_guard || true
  setup_ssh || return 1
  setup_bridge || return 1
  write_nginx_full || return 1
  setup_firewall || warn "Firewall refresh failed"
  systemctl restart xray >/dev/null 2>&1 || return 1
  wait_active xray 15 || return 1
  systemctl is-active --quiet finixo-ssh-ws || return 1
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
  self_install
  self_test
}

restart_all_inner() {
  ensure_time_sync >/dev/null 2>&1 || true
  setup_ssh || warn "sshd repair failed"
  setup_bridge || warn "bridge repair failed"
  systemctl restart xray >/dev/null 2>&1 || warn "Xray restart failed"
  systemctl restart finixo-ssh-ws >/dev/null 2>&1 || warn "SSH bridge restart failed"
  systemctl restart nginx >/dev/null 2>&1 || warn "Nginx restart failed"
  if [ "${FINIXO_EDGE:-haproxy}" = haproxy ]; then
    haproxy_pem_refresh 2>/dev/null || true
    systemctl restart haproxy >/dev/null 2>&1 || warn "HAProxy restart failed"
  fi
  wait_active xray 15 || true
  wait_active finixo-ssh-ws 15 || true
  wait_active nginx 15 || true
  self_test
}

do_uninstall() {
  need_root
  load_conf
  echo -e "${R}  This removes FinixoGate services and configuration. Nginx/UFW packages and rules stay.${N}"
  local a u
  if [ "${FINIXO_YES:-0}" = 1 ]; then a=YES; else read -r -p "  Type YES to confirm: " a || return 0; fi
  [ "$a" = YES ] || { echo "  Cancelled."; return 0; }

  remove_purge_timer 2>/dev/null || true
  remove_watchdog_timer 2>/dev/null || true
  rm -f /etc/ssh/sshd_config.d/99-finixo-emergency.conf
  rm -f /etc/sudoers.d/finixo-fx_* 2>/dev/null || true
  rm -f "$CONF_DIR/emergency-admin.cred" 2>/dev/null || true
  systemctl disable --now xray finixo-ssh-ws >/dev/null 2>&1 || true
  systemctl disable --now haproxy >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/xray.service /etc/systemd/system/finixo-ssh-ws.service
  rm -f /etc/systemd/system/haproxy.service.d/finixo.conf
  rmdir /etc/systemd/system/haproxy.service.d 2>/dev/null || true
  # keep distro haproxy package; reset to package default if present
  if [ -f /etc/haproxy/haproxy.cfg.dpkg-dist ]; then cp -a /etc/haproxy/haproxy.cfg.dpkg-dist /etc/haproxy/haproxy.cfg 2>/dev/null || true; fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl disable --now finixo-nft-guard >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/finixo-nft-guard.service /etc/nftables.d/finixo-tunnel-guard.nft
  nft delete table inet finixo >/dev/null 2>&1 || true
  rm -f "$XRAY_BIN" "$NGX_CONF" "$NGX_RATE" "$NGX_STEALTH" "$NGX_WS" "$NGX_SYSD" "$NGX_PERF" /etc/nginx/conf.d/finixo-rate.conf \
        /etc/nginx/conf.d/99-finixo-acme.conf /etc/letsencrypt/renewal-hooks/deploy/finixo-nginx.sh \
        /etc/logrotate.d/finixo-xray /etc/logrotate.d/finixo-ws "${WS_ACCESS_LOG:-/var/log/nginx/finixo-ws.log}"
  rm -rf "$XRAY_DIR" "$XRAY_ASSET" "$XRAY_LOG" "$BRIDGE_DIR" "$SITE_ROOT" /var/www/finixo-acme
  systemctl reload nginx >/dev/null 2>&1 || true

  if getent group "$SSH_GROUP" >/dev/null 2>&1; then
    if confirm "Delete all SSH tunnel-only users?"; then
      while IFS= read -r u; do
        [ -n "$u" ] || continue
        pkill -KILL -u "$u" 2>/dev/null || true
        userdel "$u" 2>/dev/null && echo "  removed $u" || true
      done < <(ssh_users)
    else
      while IFS= read -r u; do
        [ -n "$u" ] || continue
        usermod -s /usr/sbin/nologin "$u" 2>/dev/null || true
        pkill -KILL -u "$u" 2>/dev/null || true
      done < <(ssh_users)
      warn "The kept tunnel users were switched to /usr/sbin/nologin."
    fi
    groupdel "$SSH_GROUP" >/dev/null 2>&1 || warn "Group $SSH_GROUP remains because it still has members."
  fi
  rm -f "$SSH_DROPIN" "$SSH_LEGACY_DROPIN"
  if [ -f "$SSH_INCLUDE_MARKER" ]; then
    sed -i '/^# FinixoGate managed sshd_config\.d include\.$/d;/^Include \/etc\/ssh\/sshd_config\.d\/\*\.conf$/d' /etc/ssh/sshd_config 2>/dev/null || true
    rm -f "$SSH_INCLUDE_MARKER"
  fi
  if sshd -t >/dev/null 2>&1; then reload_ssh || true; fi
  userdel xray >/dev/null 2>&1 || true
  userdel finixo-bridge >/dev/null 2>&1 || true
  rm -f /etc/sysctl.d/99-finixo-harden.conf /etc/modules-load.d/finixo.conf /etc/modules-load.d/bbr.conf /etc/fail2ban/jail.d/finixo-ssh.conf /etc/cron.weekly/finixo-cert-renew

  if [ -f "$NGINX_DEFAULT_BACKUP" ] && [ ! -e /etc/nginx/sites-enabled/default ]; then
    install -d -m 755 /etc/nginx/sites-enabled || true
    cp -a "$NGINX_DEFAULT_BACKUP" /etc/nginx/sites-enabled/default 2>/dev/null || true
    nginx -t >/dev/null 2>&1 && (systemctl reload nginx >/dev/null 2>&1 || true)
  fi
  rm -rf "$CONF_DIR" "$LOCK_DIR"
  rm -f "$BIN_LINK"
  ok "FinixoGate removed. Nginx/UFW packages and firewall rules were intentionally left in place."
  return 0
}

# ----------------------------------------------------------------------------
# Status helpers (used by the TUI, the sub-menus and `finixo status`)
# ----------------------------------------------------------------------------
# two menu cells per row
trunc() { local v=$1 n=${2:-48}; if [ "${#v}" -gt "$n" ]; then echo "${v:0:n-1}…"; else echo "$v"; fi; }
svc_state() { systemctl is-active --quiet "$1" 2>/dev/null && echo on || echo off; }

# Badge: 🟢 ONLINE / 🔴 OFFLINE (plain length kept stable for box alignment)
svc_badge_plain() {
  if systemctl is-active --quiet "$1" 2>/dev/null; then echo "ONLINE "; else echo "OFFLINE"; fi
}
svc_badge_color() {
  if systemctl is-active --quiet "$1" 2>/dev/null; then
    printf '%sONLINE%s ' "$G" "$N"
  else
    printf '%sOFFLINE%s' "$R" "$N"
  fi
}



# ── Precise duration / expiry (days + hours + minutes) ───────────────
# Accepts: 30 | 7d | 12h | 90m | 1d6h | 2d12h30m | 1h30m
# Returns seconds in DUR_SECS, human text in DUR_HUMAN. 0 on failure.
parse_duration() {
  local raw=$1 d=0 h=0 m=0 rest
  DUR_SECS=0; DUR_HUMAN=""
  raw=$(printf '%s' "$raw" | tr -d '[:space:]' | tr 'A-Z' 'a-z')
  [ -n "$raw" ] || return 1
  [ "${#raw}" -le 12 ] || return 1   # absurdly long input (also keeps the arithmetic far from overflow)
  # Pure number = days (backward compatible)
  if [[ $raw =~ ^[0-9]+$ ]]; then
    d=$raw
  else
    rest=$raw
    if [[ $rest =~ ^([0-9]+)d(.*)$ ]]; then d=${BASH_REMATCH[1]}; rest=${BASH_REMATCH[2]}; fi
    if [[ $rest =~ ^([0-9]+)h(.*)$ ]]; then h=${BASH_REMATCH[1]}; rest=${BASH_REMATCH[2]}; fi
    if [[ $rest =~ ^([0-9]+)m(.*)$ ]]; then m=${BASH_REMATCH[1]}; rest=${BASH_REMATCH[2]}; fi
    [ -z "$rest" ] || return 1
  fi
  DUR_SECS=$(( 10#$d*86400 + 10#$h*3600 + 10#$m*60 ))
  [ "$DUR_SECS" -ge 60 ] || { DUR_SECS=0; return 1; }          # minimum 1 minute
  [ "$DUR_SECS" -le 315360000 ] || { DUR_SECS=0; return 1; }   # maximum 3650 days
  local parts=()
  [ "$((10#$d))" -gt 0 ] && parts+=("$((10#$d))d")
  [ "$((10#$h))" -gt 0 ] && parts+=("$((10#$h))h")
  [ "$((10#$m))" -gt 0 ] && parts+=("$((10#$m))m")
  DUR_HUMAN=$(IFS=' '; echo "${parts[*]}")
  return 0
}

# Format remaining time from ISO expiry datetime
expiry_left_text() {
  local exp=$1 now left ts
  now=$(date +%s)
  # Support both YYYY-MM-DD and YYYY-MM-DDTHH:MM:SS
  if [[ $exp =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    exp="${exp}T23:59:59"
  fi
  # An unparsable record is NOT "expired": purge_expired_clients skips it as well, so display and purge agree.
  ts=$(date -d "$exp" +%s 2>/dev/null) || { echo "INVALID"; return 0; }
  left=$(( ts - now ))
  if [ "$left" -le 0 ]; then echo "EXPIRED"; return; fi
  local d=$((left/86400)) h=$(( (left%86400)/3600 )) m=$(( (left%3600)/60 ))
  local out=""
  [ "$d" -gt 0 ] && out+="${d}d "
  [ "$h" -gt 0 ] && out+="${h}h "
  out+="${m}m"
  echo "$out"
}


# Delete one "tag|name|..." record from a pipe-delimited db file (exact field match, unique temp file)
db_drop() {
  local f=$1 tag=$2 name=$3 t
  [ -f "$f" ] || return 0
  t=$(mktemp "${f}.XXXXXX") || return 1
  awk -F'|' -v t="$tag" -v n="$name" '!($1==t && $2==n)' "$f" > "$t" 2>/dev/null || true
  chmod 600 "$t" 2>/dev/null || true
  mv -f "$t" "$f" 2>/dev/null || { rm -f "$t"; return 1; }
}

# Tunnel-only SSH users whose account expiry has been reached: kill their live sessions. New logins are
# already refused by the account expiry, but an established session would otherwise stay up for ever.
# The account itself is kept (an admin can still Renew it); removing it is an explicit Connection Control action.
purge_expired_ssh_sessions() {
  command -v ps >/dev/null 2>&1 || return 0
  local u k
  while read -r u k; do
    [ -n "$u" ] || continue
    ssh_expired "$u" || continue
    pkill -KILL -u "$u" 2>/dev/null || true
  done < <(online_ssh_sessions 2>/dev/null)
  return 0
}

# Remove Xray clients whose expiry time has passed (from EXPIRY_DB)
purge_expired_clients() {
  purge_expired_ssh_sessions || true
  # Format in EXPIRY_DB: tag|email|YYYY-MM-DDTHH:MM:SS   (or legacy YYYY-MM-DD = end of that day)
  # Expired users are removed from disk config + Xray API. Because the API only blocks NEW
  # connections, ONE batched restart is done at the end when anyone was removed, so existing
  # sessions of expired users really end (other users reconnect within seconds).
  [ -f "$EXPIRY_DB" ] && [ -f "$XRAY_CFG" ] || return 0
  local now tag email exp exp_ts changed=0 snap
  now=$(date +%s)
  snap=$(mktemp "${EXPIRY_DB}.snap.XXXXXX") || return 0
  cp -f "$EXPIRY_DB" "$snap" 2>/dev/null || { rm -f "$snap"; return 0; }
  while IFS='|' read -r tag email exp; do
    [ -n "$tag" ] && [ -n "$email" ] && [ -n "$exp" ] || continue
    if [[ $exp =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then exp="${exp}T23:59:59"; fi
    exp_ts=$(date -d "$exp" +%s 2>/dev/null) || continue
    [ "$exp_ts" -gt "$now" ] && continue   # still valid

    # Expired while DISABLED: drop the stored secret too, otherwise enabling it later would resurrect it.
    if [ -f "$DISABLED_DB" ] && awk -F'|' -v t="$tag" -v e="$email" '$1==t && $2==e {f=1} END{exit !f}' "$DISABLED_DB"; then
      db_drop "$DISABLED_DB" "$tag" "$email"
    fi
    # Expired and live: remove from config and from the running Xray.
    if jq -e --arg t "$tag" --arg n "$email" \
        '.inbounds[]|select(.tag==$t).settings.clients[]|select(.email==$n)' \
        "$XRAY_CFG" >/dev/null 2>&1; then
      xray_api_rm_user "$tag" "$email" 2>/dev/null || true
      if cfg_apply_disk --arg t "$tag" --arg n "$email" \
          '(.inbounds[]|select(.tag==$t).settings.clients) |= map(select(.email!=$n))' >/dev/null 2>&1; then
        changed=1
      else
        continue   # keep the record, retry on the next run
      fi
    fi
    db_drop "$EXPIRY_DB" "$tag" "$email"
  done < "$snap"
  rm -f "$snap"

  if [ "$changed" = 1 ]; then
    systemctl restart xray >/dev/null 2>&1 && wait_active xray 15 || true
  fi
  return 0
}


# ═══════════════════════════════════════════════════════════════════════════
# EXACT LIVE ONLINE COUNTER
#  Xray : Stats API  user>>>EMAIL>>>online  (policy statsUserOnline +
#         trustedXForwardedFor; Nginx hands Xray the real peer IP). A user is
#         online while at least one of its connections is open — even idle —
#         and drops a few seconds after the last connection closes.
#  SSH  : live sshd processes owned by tunnel-only users (one per connection).
#         OS logins outside the tunnel-only group are never counted.
# ═══════════════════════════════════════════════════════════════════════════
XRAY_WS_TAG_RE='^(vless|vmess|trojan|ss)-ws$'

# 0 when Xray is configured to expose the live online stats.
online_stats_ready() {
  [ -f "$XRAY_CFG" ] || return 1
  jq -e --arg re "$XRAY_WS_TAG_RE" '
    (.policy.levels["0"].statsUserOnline == true)
    and ([.inbounds[]? | select((.tag // "") | test($re))
          | select((.streamSettings.sockopt.trustedXForwardedFor // []) | any(.[]; . == "X-Forwarded-For"))]
         | length == 4)' "$XRAY_CFG" >/dev/null 2>&1
}

# One-time (idempotent) upgrade for existing installs. Restarts Xray once.
ensure_xray_online_stats() {   # arg "disk": only write the file (the caller restarts Xray itself)
  [ -f "$XRAY_CFG" ] || return 1
  online_stats_ready && return 0
  local ap=cfg_apply; [ "${1:-}" = disk ] && ap=cfg_apply_disk
  info "Enabling the exact live online counter in Xray..."
  "$ap" --arg re "$XRAY_WS_TAG_RE" '
    .policy = (.policy // {})
    | .policy.levels = (.policy.levels // {})
    | .policy.levels["0"] = ((.policy.levels["0"] // {}) + {"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true})
    | .inbounds |= map(
        if ((.tag // "") | test($re)) then
          .streamSettings.sockopt = ((.streamSettings.sockopt // {}) + {"trustedXForwardedFor":["X-Forwarded-For"]})
        else . end)' || return 1
  # Hardening: make Nginx overwrite X-Forwarded-For with the real peer IP.
  if grep -qs 'proxy_add_x_forwarded_for' "$NGX_WS" 2>/dev/null; then
    write_nginx_full >/dev/null 2>&1 || warn "Could not refresh the Nginx config (run: finixo repair)"
  fi
  online_stats_ready
}

# Connection policy: idle tunnels survive 30 minutes (Xray's default is 5, which silently cut quiet
# connections and made apps reconnect), slow mobile starts get 8 s for the handshake (default 4).
# Existing explicit values are never overwritten.
xray_tuning_ready() {
  [ -f "$XRAY_CFG" ] || return 1
  jq -e '(.policy.levels["0"].connIdle != null) and (.policy.levels["0"].handshake != null)' "$XRAY_CFG" >/dev/null 2>&1
}
XRAY_JQ_TUNE='.policy = (.policy // {})
  | .policy.levels = (.policy.levels // {})
  | .policy.levels["0"] = ((.policy.levels["0"] // {}) | .handshake = (.handshake // 8) | .connIdle = (.connIdle // 1800))'
ensure_xray_tuning() {   # arg "disk": only write the file (the caller restarts Xray itself)
  [ -f "$XRAY_CFG" ] || return 1
  xray_tuning_ready && return 0
  if [ "${1:-}" = disk ]; then cfg_apply_disk "$XRAY_JQ_TUNE"; else
    info "Tuning Xray connection policy (one-time restart)..."
    cfg_apply "$XRAY_JQ_TUNE"
  fi
}

# One restart for every pending Xray runtime upgrade (online counter + connection policy).
ensure_xray_runtime() {   # arg "disk": only write the file (the caller restarts Xray itself)
  [ -f "$XRAY_CFG" ] || return 1
  if online_stats_ready && xray_tuning_ready; then return 0; fi
  if online_stats_ready; then ensure_xray_tuning "${1:-}"; return; fi
  if xray_tuning_ready; then ensure_xray_online_stats "${1:-}"; return; fi
  local ap=cfg_apply; [ "${1:-}" = disk ] && ap=cfg_apply_disk
  info "Applying the Xray runtime upgrade: exact online counter + connection policy..."
  "$ap" --arg re "$XRAY_WS_TAG_RE" "$XRAY_JQ_TUNE"'
    | .policy.levels["0"] = ((.policy.levels["0"] // {}) + {"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true})
    | .inbounds |= map(
        if ((.tag // "") | test($re)) then
          .streamSettings.sockopt = ((.streamSettings.sockopt // {}) + {"trustedXForwardedFor":["X-Forwarded-For"]})
        else . end)' || return 1
  if grep -qs 'proxy_add_x_forwarded_for' "$NGX_WS" 2>/dev/null; then
    write_nginx_full >/dev/null 2>&1 || warn "Could not refresh the Nginx config (run: finixo repair)"
  fi
  online_stats_ready && xray_tuning_ready
}

# Every account email (and the SS key email) that Xray knows about.
xray_emails_of_tag() {
  [ -f "$XRAY_CFG" ] || return 0
  jq -r --arg t "$1" '.inbounds[]? | select(.tag==$t)
    | ((.settings.clients[]? | .email), .settings.email)
    | select(. != null and . != "")' "$XRAY_CFG" 2>/dev/null
}
xray_all_emails() {
  local t
  for t in vless-ws vmess-ws trojan-ws ss-ws; do xray_emails_of_tag "$t"; done | sort -u
}

# Emails with an open connection right now (one per line, unique).
online_xray_emails() {
  [ -x "$XRAY_BIN" ] && [ -f "$XRAY_CFG" ] || return 1
  local srv="127.0.0.1:${XRAY_API_PORT:-10085}" out e v
  # Prefer batch IP list API (one call → all users + IPs) when available (Xray ≥ ~26.x)
  out=$(timeout 5 "$XRAY_BIN" api statsonlineiplist --server="$srv" -all 2>/dev/null) || out=""
  if jq -e '.users | type=="array"' <<< "$out" >/dev/null 2>&1; then
    jq -r '.users[]? | select((.ips|length)>0) | .email // empty' <<< "$out" | sort -u \
      | grep -Fxf <(xray_all_emails) || true
    return 0
  fi
  out=$(timeout 4 "$XRAY_BIN" api statsgetallonlineusers --server="$srv" 2>/dev/null) || out=""
  if jq -e 'type=="object"' <<< "$out" >/dev/null 2>&1; then
    jq -r '.users[]? | select(startswith("user>>>") and endswith(">>>online"))
           | sub("^user>>>"; "") | sub(">>>online$"; "")' <<< "$out" | sort -u \
      | grep -Fxf <(xray_all_emails) || true
    return 0
  fi
  ss -ltnH 2>/dev/null | gq -qE ":${XRAY_API_PORT:-10085}[[:space:]]" || return 0
  while IFS= read -r e; do
    [ -n "$e" ] || continue
    v=$(timeout 2 "$XRAY_BIN" api statsonline --server="$srv" -email "$e" 2>/dev/null | jq -r '.stat.value // 0' 2>/dev/null)
    if [[ ${v:-0} =~ ^[0-9]+$ ]] && [ "${v:-0}" -gt 0 ]; then printf '%s\n' "$e"; fi
  done < <(xray_all_emails)
  return 0
}

# Distinct client IPs for one email (shared config = multiple devices).
# Order: iplist length → statsonline value → 0
xray_online_ips() {
  local email=$1 srv="127.0.0.1:${XRAY_API_PORT:-10085}" out v n
  out=$(timeout 3 "$XRAY_BIN" api statsonlineiplist --server="$srv" -email "$email" 2>/dev/null) || out=""
  n=$(jq -r '(.ips // .stat.ips // {}) | if type=="object" then keys|length elif type=="array" then length else 0 end' <<< "$out" 2>/dev/null)
  if [[ ${n:-0} =~ ^[0-9]+$ ]] && [ "${n:-0}" -gt 0 ]; then echo "$n"; return 0; fi
  # Some builds return map under .ips as object ip->timestamp
  n=$(jq -r 'if .ips then (.ips|keys|length) elif .stat.value then .stat.value else 0 end' <<< "$out" 2>/dev/null)
  if [[ ${n:-0} =~ ^[0-9]+$ ]] && [ "${n:-0}" -gt 0 ]; then echo "$n"; return 0; fi
  v=$(timeout 3 "$XRAY_BIN" api statsonline --server="$srv" -email "$email" 2>/dev/null | jq -r '.stat.value // 0' 2>/dev/null)
  [[ ${v:-0} =~ ^[0-9]+$ ]] || v=0
  echo "$v"
}

# HAProxy stick-table: unique client IPs with live WS (conn_cur>0) per protocol backend.
# Works even when several people share ONE UUID — each phone = different src IP at the edge.
HAP_SOCK=/run/haproxy/admin.sock
haproxy_table_live_ips() {  # $1 = table name e.g. st_vless → count of keys with conn_cur>0
  local table=$1 sock=${HAP_SOCK} line ip n=0
  [ -S "$sock" ] || { echo 0; return 0; }
  while IFS= read -r line; do
    # lines like: 0x...: key=1.2.3.4 use=0 exp=... conn_cur=1 ...
    [[ "$line" == *conn_cur=* ]] || continue
    if [[ "$line" =~ conn_cur=([0-9]+) ]]; then
      [ "${BASH_REMATCH[1]}" -gt 0 ] || continue
      n=$((n+1))
    fi
  done < <(echo "show table $table" | timeout 2 socat - "UNIX-CONNECT:$sock" 2>/dev/null || echo "show table $table" | timeout 2 nc -U "$sock" 2>/dev/null || true)
  echo "$n"
}

haproxy_online_devices() {
  # Unique live client IPs across all protocol stick-tables (one phone on 2 protocols = 1 device)
  local sock=${HAP_SOCK:-/run/haproxy/admin.sock} line ip
  local -A seen=()
  [ -S "$sock" ] || { echo 0; return 0; }
  for t in st_vless st_vmess st_trojan st_ss st_ssh; do
    while IFS= read -r line; do
      [[ "$line" == *conn_cur=* ]] || continue
      if [[ "$line" =~ conn_cur=([0-9]+) ]]; then
        [ "${BASH_REMATCH[1]}" -gt 0 ] || continue
      else
        continue
      fi
      # IPv4 or IPv6 stick-table keys
      if [[ "$line" =~ key=([^[:space:]]+) ]]; then
        ip="${BASH_REMATCH[1]%:}"
        [ -n "$ip" ] && seen["$ip"]=1
      fi
    done < <(echo "show table $t" | timeout 2 socat - "UNIX-CONNECT:$sock" 2>/dev/null || true)
  done
  echo ${#seen[@]}
}

haproxy_online_by_proto() {  # print: proto count
  printf 'vless %s\n' "$(haproxy_table_live_ips st_vless)"
  printf 'vmess %s\n' "$(haproxy_table_live_ips st_vmess)"
  printf 'trojan %s\n' "$(haproxy_table_live_ips st_trojan)"
  printf 'ss %s\n' "$(haproxy_table_live_ips st_ss)"
  printf 'ssh %s\n' "$(haproxy_table_live_ips st_ssh)"
}


# "user connections" per line for tunnel-only SSH users with a live session.
online_ssh_sessions() {
  command -v ps >/dev/null 2>&1 || return 0
  awk 'NR==FNR { ok[$1]=1; next }
       ($2=="sshd" || $2=="sshd-session") && ($1 in ok) { c[$1]++ }
       END { for (u in c) print u, c[u] }' \
    <(ssh_users 2>/dev/null) <(ps -eo user:32=,comm= 2>/dev/null) | sort
}

# Total users online right now (Xray users + SSH-WS users).
count_online_connections() {
  # Account-level: distinct Xray emails online + distinct SSH tunnel users
  local x s
  x=$(online_xray_emails 2>/dev/null | sed '/^$/d' | wc -l)
  s=$(online_ssh_sessions 2>/dev/null | sed '/^$/d' | wc -l)
  echo $(( ${x:-0} + ${s:-0} ))
}

# Device-level: sum of unique live IPs (shared config counted as many devices)
count_online_devices() {
  local d hx xs=0
  # Prefer HAProxy edge tables (sees real client IP even for shared UUID)
  if [ -S "${HAP_SOCK:-/run/haproxy/admin.sock}" ]; then
    d=$(haproxy_online_devices 2>/dev/null || echo 0)
    [[ $d =~ ^[0-9]+$ ]] || d=0
    if [ "$d" -gt 0 ]; then echo "$d"; return 0; fi
  fi
  # Fallback: sum Xray per-email IP counts
  while IFS= read -r e; do
    [ -n "$e" ] || continue
    hx=$(xray_online_ips "$e" 2>/dev/null || echo 0)
    xs=$((xs + ${hx:-0}))
  done < <(online_xray_emails 2>/dev/null)
  s=$(online_ssh_sessions 2>/dev/null | awk '{s+=$2} END{print s+0}')
  echo $(( xs + ${s:-0} ))
}

# Cache used by the list screens: call refresh_online_set once, then online_tag per user.
ONL_READY=0; ONL_SET=""; ONL_DUP=""
declare -gA ONL_IPC=()   # email -> distinct client IPs, filled once per refresh_online_set
refresh_online_set() {
  ONL_READY=0; ONL_SET=""; ONL_IPC=(); ONL_DUP=""
  online_stats_ready && ONL_READY=1
  ONL_SET=$(online_xray_emails 2>/dev/null || true)
  local srv="127.0.0.1:${XRAY_API_PORT:-10085}" out
  # One-shot fill of IP counts from batch API
  if [ "$ONL_READY" = 1 ] && [ -x "$XRAY_BIN" ]; then
    out=$(timeout 5 "$XRAY_BIN" api statsonlineiplist --server="$srv" -all 2>/dev/null) || out=""
    if jq -e '.users | type=="array"' <<< "$out" >/dev/null 2>&1; then
      while IFS=$'\t' read -r _e _n; do
        [ -n "$_e" ] || continue
        [[ ${_n:-0} =~ ^[0-9]+$ ]] && ONL_IPC["$_e"]=$_n
      done < <(jq -r '.users[]? | select(.email!=null) | [.email, ((.ips|length)//0)] | @tsv' <<< "$out" 2>/dev/null)
    elif [ -n "$ONL_SET" ] && command -v xargs >/dev/null 2>&1; then
      while IFS=$'\t' read -r _e _v; do
        [[ ${_v:-} =~ ^[0-9]+$ ]] && ONL_IPC["$_e"]=$_v
      done < <(printf '%s\n' "$ONL_SET" | xargs -r -d '\n' -P 8 -I{} sh -c \
          'v=$(timeout 3 "$0" api statsonline --server="$1" -email "$2" 2>/dev/null | jq -r ".stat.value // 0" 2>/dev/null); printf "%s\t%s\n" "$2" "${v:-0}"' \
          "$XRAY_BIN" "$srv" {} 2>/dev/null)
    fi
  fi
  ONL_DUP=$({ local tg; for tg in vless-ws vmess-ws trojan-ws ss-ws; do xray_emails_of_tag "$tg" | sort -u; done; } | sort | uniq -d)
}

online_tag() {   # $1 = email -> coloured " ● ONLINE" / " ○ offline"
  local n=$1 k
  [ "$ONL_READY" = 1 ] || return 0
  if grep -Fxq -- "$n" <<< "$ONL_SET"; then
    k=${ONL_IPC[$n]:-}
    [[ $k =~ ^[0-9]+$ ]] || k=$(xray_online_ips "$n")
    printf ' %s● ONLINE%s' "$G" "$N"
    if [ "${k:-0}" -gt 1 ]; then printf ' %s(%s IPs)%s' "$D" "$k" "$N"; fi
    if grep -Fxq -- "$n" <<< "${ONL_DUP:-}"; then printf ' %s≈ same name on several protocols%s' "$Y" "$N"; fi
  else
    printf ' %s○ offline%s' "$D" "$N"
  fi
}

# Live summary block (needs refresh_online_set first).
print_online_summary() {
  local tag n c names line u k x_tot s_tot=0 s_conn=0
  echo -e "  ${W}━━ ONLINE NOW (live) ━━${N}"
  if [ "$ONL_READY" != 1 ]; then
    echo -e "  ${Y}Xray live counter is OFF — run: finixo repair  (one-time Xray restart)${N}"
  fi
  for tag in vless-ws vmess-ws trojan-ws ss-ws; do
    c=0; names=""
    while IFS= read -r n; do
      [ -n "$n" ] || continue
      if grep -Fxq -- "$n" <<< "$ONL_SET"; then c=$((c+1)); names+="$n "; fi
    done < <(xray_emails_of_tag "$tag")
    printf '  %-12s %s%s%s online' "${tag%-ws}" "$G" "$c" "$N"
    if [ "$tag" = ss-ws ] && [ "$c" -gt 0 ]; then names="shared key · $(xray_online_ips "${names%% *}") device IP(s) "; fi
    if [ -n "$names" ]; then printf '  %s(%s)%s' "$D" "${names% }" "$N"; fi
    printf '\n'
  done
  line=""
  while read -r u k; do
    [ -n "$u" ] || continue
    s_tot=$((s_tot+1)); s_conn=$((s_conn+k)); line+="$u×$k "
  done < <(online_ssh_sessions)
  printf '  %-12s %s%s%s online' "ssh-ws" "$G" "$s_tot" "$N"
  if [ -n "$line" ]; then printf '  %s(%s)%s' "$D" "${line% }" "$N"; fi
  printf '\n'
  x_tot=$(sed '/^$/d' <<< "$ONL_SET" | wc -l)
  local devs=0 hx
  # Device total: prefer HAProxy stick-tables (unique src IP with live tunnel)
  if [ -S "${HAP_SOCK:-/run/haproxy/admin.sock}" ]; then
    devs=$(haproxy_online_devices 2>/dev/null || echo 0)
  fi
  if ! [[ ${devs:-0} =~ ^[0-9]+$ ]] || [ "${devs:-0}" -eq 0 ]; then
    devs=0
    for n in $ONL_SET; do
      [ -n "$n" ] || continue
      hx=${ONL_IPC[$n]:-$(xray_online_ips "$n" 2>/dev/null || echo 0)}
      devs=$((devs + ${hx:-0}))
    done
    devs=$((devs + s_conn))
  fi
  echo -e "  ${C}TOTAL ONLINE ACCOUNTS: ${W}$(( x_tot + s_tot ))${N}  ${D}(Xray ${x_tot} · SSH ${s_tot})${N}"
  echo -e "  ${C}TOTAL ONLINE DEVICES:  ${W}${devs}${N}  ${D}(unique IPs · shared config counted separately)${N}"
  if [ -S "${HAP_SOCK:-/run/haproxy/admin.sock}" ]; then
    echo -e "  ${D}HAProxy tables:${N} $(haproxy_online_by_proto 2>/dev/null | tr '\n' ' ')"
  fi
}

# CLI: finixo online
show_online() {
  refresh_online_set
  print_online_summary
}

# Count Xray clients by inbound tag (0 if missing)
count_xray_clients() {
  local tag=$1
  [ -f "$XRAY_CFG" ] || { echo 0; return; }
  jq -r --arg t "$tag" '[.inbounds[]? | select(.tag==$t) | .settings.clients[]?] | length' "$XRAY_CFG" 2>/dev/null || echo 0
}

count_ssh_tunnel_users() {
  # One line per tunnel-only user: ssh_users already merges group members + primary-group users.
  # (The old name-vs-group-line word match counted wrongly when a user was called "tunnel", "only", "x" ...)
  local n
  n=$(ssh_users 2>/dev/null | sed '/^$/d' | wc -l)
  echo $(( ${n//[[:space:]]/} + 0 ))
}

cert_days_left() {
  [ -f "$TLS_CRT" ] || { echo "n/a"; return; }
  local end now left
  end=$(openssl x509 -in "$TLS_CRT" -noout -enddate 2>/dev/null | cut -d= -f2) || { echo "n/a"; return; }
  end=$(date -d "$end" +%s 2>/dev/null) || { echo "n/a"; return; }
  now=$(date +%s)
  left=$(( (end - now) / 86400 ))
  if [ "$left" -lt 0 ]; then echo "EXPIRED"; else echo "${left}d"; fi
}

# Precise cert health for dashboard:
#   ONLINE  = file present + not expired (openssl checkend 0)
#   OFFLINE = missing or expired
# Returns plain text for box width + colored via cert_badge_color
cert_badge_plain() {
  if [ ! -f "$TLS_CRT" ] || [ ! -f "$TLS_KEY" ]; then
    echo "OFFLINE"
    return
  fi
  if openssl x509 -checkend 0 -noout -in "$TLS_CRT" >/dev/null 2>&1; then
    echo "ONLINE "
  else
    echo "OFFLINE"
  fi
}
cert_badge_color() {
  if [ ! -f "$TLS_CRT" ] || [ ! -f "$TLS_KEY" ]; then
    printf '%sOFFLINE%s' "$R" "$N"
    return
  fi
  if openssl x509 -checkend 0 -noout -in "$TLS_CRT" >/dev/null 2>&1; then
    printf '%sONLINE%s ' "$G" "$N"
  else
    printf '%sOFFLINE%s' "$R" "$N"
  fi
}
cert_kind_short() {
  local issuer subject
  [ -f "$TLS_CRT" ] || { echo "none"; return; }
  issuer=$(openssl x509 -issuer -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^issuer=//')
  subject=$(openssl x509 -subject -noout -in "$TLS_CRT" 2>/dev/null | sed 's/^subject=//')
  if [ "$issuer" = "$subject" ]; then echo "self-signed"
  elif echo "$issuer" | gq -qi "Let's Encrypt\|R3\|R10\|E1\|E5\|ISRG"; then echo "Let's Encrypt"
  else echo "CA"; fi
}



menu_require_installed() {
  is_installed && return 0
  err "Install first (menu $(menu_no 'Install / Reinstall'))."
  pause
  return 1
}


# ----------------------------------------------------------------------------
# DEEP AUDIT — exhaustive live probe (menu 15 / finixo deep-test)
# ----------------------------------------------------------------------------
deep_audit() {
  load_conf
  local fails=0 passes=0 warns=0
  _ok(){ ok "$1"; passes=$((passes+1)); }
  _bad(){ err "$1"; fails=$((fails+1)); }
  _wrn(){ warn "$1"; warns=$((warns+1)); }

  echo -e "\n${R}╔════════════════════════════════════════════════════════════╗${N}"
  echo -e "${R}║${W}         FINIXO GATE — DEEP AUDIT v$VERSION             ${R}║${N}"
  echo -e "${R}╚════════════════════════════════════════════════════════════╝${N}\n"

  # Layer 1: binaries
  echo -e "${C}▸ Layer 1 — Binaries & packages${N}"
  for b in xray nginx python3 openssl jq curl ss ufw; do
    command -v "$b" >/dev/null 2>&1 && _ok "binary: $b" || _bad "missing binary: $b"
  done
  [ -x "$XRAY_BIN" ] && _ok "Xray path executable" || _bad "Xray not executable"
  "$XRAY_BIN" version >/dev/null 2>&1 && _ok "Xray runs" || _bad "Xray version failed"

  # Layer 2: files & perms
  echo -e "\n${C}▸ Layer 2 — Files & permissions${N}"
  for f in "$ENV_FILE" "$TLS_CRT" "$TLS_KEY" "$XRAY_CFG" "$NGX_CONF" "$BRIDGE" "$HOLD"; do
    [ -e "$f" ] && _ok "exists: $f" || _bad "missing: $f"
  done
  [ "$(stat -c '%a' "$TLS_KEY" 2>/dev/null)" = 600 ] && _ok "TLS key mode 600" || _bad "TLS key mode not 600"
  [ "$(stat -c '%a' "$ENV_FILE" 2>/dev/null)" = 600 ] && _ok "ENV mode 600" || _bad "ENV mode not 600"

  # Layer 3: services
  echo -e "\n${C}▸ Layer 3 — Services${N}"
  for s in nginx xray finixo-ssh-ws; do
    systemctl is-active --quiet "$s" && _ok "active: $s" || _bad "inactive: $s"
    systemctl is-enabled --quiet "$s" 2>/dev/null && _ok "enabled: $s" || _wrn "not enabled: $s"
  done

    if [ "${FINIXO_EDGE:-haproxy}" = haproxy ]; then
    systemctl is-active --quiet haproxy && _ok "active: haproxy (edge)" || _bad "inactive: haproxy (edge)"
    systemctl is-enabled --quiet haproxy 2>/dev/null && _ok "enabled: haproxy" || _wrn "not enabled: haproxy"
    if command -v haproxy >/dev/null 2>&1 && [ -f "${HAP_CFG:-/etc/haproxy/haproxy.cfg}" ]; then
      haproxy -c -f "${HAP_CFG:-/etc/haproxy/haproxy.cfg}" >/dev/null 2>&1 && _ok "haproxy.cfg validates" || _bad "haproxy.cfg invalid"
    fi
  fi

# Layer 4: config validity
  echo -e "\n${C}▸ Layer 4 — Configuration validity${N}"
  validate_xray_config_file "$XRAY_CFG" && _ok "Xray JSON valid" || _bad "Xray JSON invalid"
  nginx -t >/dev/null 2>&1 && _ok "Nginx -t OK" || _bad "Nginx -t FAIL"
  install -d -m 755 /run/sshd 2>/dev/null || true
  sshd -t >/dev/null 2>&1 && _ok "sshd -t OK" || _bad "sshd -t FAIL"

  # Layer 5: localhost binding (security critical)
  echo -e "\n${C}▸ Layer 5 — Localhost-only binding (security)${N}"
  local exposed p
  for p in ${P_VLESS:-} ${P_VMESS:-} ${P_TROJAN:-} ${P_SS:-} ${P_SSHWS:-}; do
    [ -n "$p" ] || continue
    if ss -ltnH 2>/dev/null | gq -qE "127\\.0\\.0\\.1:$p\\b"; then
      _ok "port $p on 127.0.0.1"
    else
      _bad "port $p NOT on 127.0.0.1"
    fi
  done
  exposed=$(ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E ":($P_VLESS|$P_VMESS|$P_TROJAN|$P_SS|$P_SSHWS)$" | grep -vE '^(127\.0\.0\.1:|\[::1\]:)' || true)
  [ -z "$exposed" ] && _ok "no internal ports public" || _bad "exposed: $exposed"

  # Layer 6: TLS / HTTP surface
  echo -e "\n${C}▸ Layer 6 — HTTP/TLS surface${N}"
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/ 2>/dev/null || true)
  [ "$code" = 200 ] && _ok "HTTP :80 decoy $code" || _bad "HTTP :80 got ${code:-none}"
  code=$(curl -sSk -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1/ 2>/dev/null || true)
  [ "$code" = 200 ] && _ok "HTTPS :443 decoy $code" || _bad "HTTPS :443 got ${code:-none}"
  if [ -f "$TLS_CRT" ] && openssl x509 -in "$TLS_CRT" -noout -checkend 86400 >/dev/null 2>&1; then
    _ok "certificate valid >24h"
  else
    _bad "certificate missing or expiring <24h"
  fi

  # Layer 7: WebSocket 101 per protocol
  echo -e "\n${C}▸ Layer 7 — WebSocket 101 upgrades${N}"
  local name pth
  local -a R3
  for name in "VLESS:$WSP_VLESS" "VMess:$WSP_VMESS" "Trojan:$WSP_TROJAN" "SS:$WSP_SS" "SSH:$WSP_SSH"; do
    pth=${name#*:}; name=${name%%:*}
    mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$pth" $([ "$name" = SSH ] && echo ssh || true))
    if [[ "${R3[0]:-}" == *101* ]]; then
      _ok "$name path $pth → 101"
    else
      _bad "$name path $pth → ${R3[0]:-no answer}"
    fi
  done

  # Layer 8: E2E data path
  echo -e "\n${C}▸ Layer 8 — End-to-end data path${N}"
  for proto in vless vmess trojan ss; do
    if protocol_e2e_probe "$proto"; then passes=$((passes+1)); else fails=$((fails+1)); fi
  done

  # Layer 9: SSH policy
  echo -e "\n${C}▸ Layer 9 — SSH tunnel-only policy${N}"
  [ -x "$HOLD" ] && _ok "ForceCommand hold present" || _bad "hold missing"
  grep -q "ForceCommand $HOLD" "$SSH_DROPIN" 2>/dev/null && _ok "ForceCommand in drop-in" || _bad "ForceCommand missing"
  getent group "${SSH_GROUP:-tunnel-only}" >/dev/null 2>&1 && _ok "group ${SSH_GROUP:-tunnel-only}" || _bad "SSH group missing"

  # Layer 10: time + harden
  echo -e "\n${C}▸ Layer 10 — Time & harden profile${N}"
  if ensure_time_sync >/dev/null 2>&1; then _ok "NTP/time OK"; else _wrn "time sync uncertain (VMess sensitive)"; fi
  if [ -f /etc/sysctl.d/99-finixo-harden.conf ]; then _ok "sysctl harden present"; else _wrn "run: finixo harden"; fi
  systemctl is-active --quiet fail2ban 2>/dev/null && _ok "fail2ban active" || _wrn "fail2ban inactive"
  sysctl net.ipv4.tcp_congestion_control 2>/dev/null | gq -q bbr && _ok "BBR active" || _wrn "BBR inactive"

  echo
  echo -e "  ${W}DEEP AUDIT RESULT${N}  ${G}pass=$passes${N}  ${R}fail=$fails${N}  ${Y}warn=$warns${N}"
  if [ "$fails" -eq 0 ]; then
    ok "ALL CRITICAL CHECKS PASSED — stack is healthy."
  else
    warn "$fails critical failure(s). Fix before production use."
  fi
  return "$fails"
}

# ----------------------------------------------------------------------------
# IRON TEST — maximum-strict production gate (menu 16 / finixo strict-test)
# Runs Deep Audit + Self-test + additional adversarial / stress / security probes.
# Any failure → non-zero exit. Warnings on critical items are promoted to fails.
# ----------------------------------------------------------------------------
iron_test() {
  load_conf
  local fails=0 passes=0 warns=0
  local name pth code i rc exposed pc pk want perms hdr tmp
  local -a R3

  _ok()  { ok  "$1"; passes=$((passes+1)); }
  _bad() { err "$1"; fails=$((fails+1)); }
  _wrn() { warn "$1"; warns=$((warns+1)); }
  _req() { local l=$1; shift; if "$@"; then _ok "$l"; else _bad "$l"; fi; }

  echo -e "\n${R}╔════════════════════════════════════════════════════════════╗${N}"
  echo -e "${R}║${W}    FINIXO GATE — IRON TEST (STRICT MAX) v$VERSION    ${R}║${N}"
  echo -e "${R}╚════════════════════════════════════════════════════════════╝${N}"
  echo -e "${D}  Adversarial · stress · security · integrity · no soft-pass${N}\n"

  [ -n "${SERVER_ADDR:-}" ] || { _bad "SERVER_ADDR missing"; echo; echo -e "  ${R}IRON TEST ABORTED${N}"; return 1; }

  # ── Phase 0: baseline deep + self ──────────────────────────────────────────
  echo -e "${C}▸ Phase 0 — Baseline Deep Audit + Self-test${N}"
  if deep_audit; then _ok "Deep Audit: all critical passed"
  else _bad "Deep Audit reported critical failures"; fi
  echo
  # self_test increments its own counters to stdout; capture exit only
  if self_test; then _ok "Self-test: all critical passed"
  else _bad "Self-test reported critical failures"; fi

  # ── Phase 1: cryptographic integrity ───────────────────────────────────────
  echo -e "\n${C}▸ Phase 1 — Cryptographic integrity${N}"
  _req "TLS cert readable" test -r "$TLS_CRT"
  _req "TLS key readable" test -r "$TLS_KEY"
  if openssl x509 -in "$TLS_CRT" -noout >/dev/null 2>&1; then _ok "cert parses as X.509"
  else _bad "cert does not parse as X.509"; fi
  if openssl pkey -in "$TLS_KEY" -noout >/dev/null 2>&1; then _ok "key parses as private key"
  else _bad "key does not parse as private key"; fi
  pc=$(openssl x509 -in "$TLS_CRT" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')
  pk=$(openssl pkey -in "$TLS_KEY" -pubout 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')
  if [ -n "$pc" ] && [ "$pc" = "$pk" ]; then _ok "cert/key cryptographic match"
  else _bad "cert/key MISMATCH (broken TLS)"; fi
  want=$(cert_sha256 2>/dev/null || true)
  if [ -n "$want" ] && [ "${#want}" -eq 64 ]; then _ok "SHA256 fingerprint length 64"
  else _bad "SHA256 fingerprint invalid"; fi
  # Must not expire within 7 days under iron rules
  if openssl x509 -checkend $((7*86400)) -noout -in "$TLS_CRT" 2>/dev/null; then
    _ok "certificate valid ≥7 days"
  else _bad "certificate expires within 7 days"; fi

  # ── Phase 2: permission lockdown ───────────────────────────────────────────
  echo -e "\n${C}▸ Phase 2 — Permission lockdown${N}"
  perms=$(stat -c '%a' "$TLS_KEY" 2>/dev/null || echo 000)
  _req "TLS key mode exactly 600" test "$perms" = 600
  perms=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || echo 000)
  _req "paths.env mode exactly 600" test "$perms" = 600
  perms=$(stat -c '%a' "$XRAY_CFG" 2>/dev/null || echo 000)
  if [ "$perms" = 600 ] || [ "$perms" = 640 ] || [ "$perms" = 644 ]; then
    _ok "Xray config mode $perms (acceptable)"
  else _bad "Xray config mode unsafe: $perms"; fi
  # No world-writable on critical paths
  for f in "$TLS_KEY" "$ENV_FILE" "$XRAY_CFG" "$BRIDGE" "$HOLD" "$NGX_CONF"; do
    [ -e "$f" ] || continue
    if [ -w "$f" ] && [ "$(stat -c '%a' "$f" | cut -c3)" = 7 ]; then
      _bad "world-writable critical file: $f"
    else
      _ok "not world-writable: $(basename "$f")"
    fi
  done
  _req "systemd unit xray.service present" test -f /etc/systemd/system/xray.service
  _req "systemd unit finixo-ssh-ws.service present" test -f /etc/systemd/system/finixo-ssh-ws.service

  # ── Phase 3: security surface (adversarial HTTP) ───────────────────────────
  echo -e "\n${C}▸ Phase 3 — Adversarial HTTP surface${N}"
  # Wrong / random path must NOT return 101
  mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "/iron-fake-path-$RANDOM" 2>/dev/null || true)
  if [[ "${R3[0]:-}" == *101* ]]; then
    _bad "random path returned 101 (path routing leak)"
  else
    _ok "random path rejected (no 101 leak)"
  fi
  # Path traversal attempts
  for pth in "/../etc/passwd" "//${WSP_VLESS}" "/%2e%2e/${WSP_VLESS#/}"; do
    mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$pth" 2>/dev/null || true)
    if [[ "${R3[0]:-}" == *101* ]]; then
      _bad "path-traversal got 101: $pth"
    else
      _ok "path-traversal blocked: $pth"
    fi
  done
  # Decoy must not expose internal markers
  tmp=$(curl -sSk --max-time 5 https://127.0.0.1/ 2>/dev/null || true)
  if echo "$tmp" | gq -qiE 'xray|vless|trojan|shadowsocks|1000[0-3]|finixo/paths'; then
    _bad "decoy page leaks internal markers"
  else
    _ok "decoy page has no internal markers"
  fi
  # Security headers on HTTPS decoy
  hdr=$(curl -sSk -D - -o /dev/null --max-time 5 https://127.0.0.1/ 2>/dev/null || true)
  echo "$hdr" | gq -qi 'strict-transport-security' && _ok "HSTS header present" || _wrn "HSTS header missing"
  echo "$hdr" | gq -qi 'x-content-type-options' && _ok "X-Content-Type-Options present" || _wrn "X-Content-Type-Options missing"

  # ── Phase 4: protocol stress (rapid WS 101) ────────────────────────────────
  echo -e "\n${C}▸ Phase 4 — Protocol stress (5× rapid WS upgrades)${N}"
  for name in "VLESS:$WSP_VLESS" "VMess:$WSP_VMESS" "Trojan:$WSP_TROJAN" "SS:$WSP_SS" "SSH:$WSP_SSH"; do
    pth=${name#*:}; name=${name%%:*}
    rc=0
    for i in 1 2 3 4 5; do
      mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$pth" $([ "$name" = SSH ] && echo ssh || true) 2>/dev/null || true)
      if [[ "${R3[0]:-}" != *101* ]]; then rc=1; break; fi
    done
    if [ "$rc" -eq 0 ]; then _ok "$name stress 5/5 → 101"
    else _bad "$name stress failed at attempt $i (${R3[0]:-no answer})"; fi
  done

  # ── Phase 5: binding & exposure (strict) ───────────────────────────────────
  echo -e "\n${C}▸ Phase 5 — Binding & public exposure${N}"
  for p in $P_VLESS $P_VMESS $P_TROJAN $P_SS $P_SSHWS; do
    if ss -ltnH 2>/dev/null | gq -qE "127\.0\.0\.1:$p\b"; then
      _ok "internal $p → 127.0.0.1"
    else
      _bad "internal $p NOT listening on 127.0.0.1"
    fi
  done
  exposed=$(ss -ltnH 2>/dev/null | awk '{print $4}' \
    | grep -E ":($P_VLESS|$P_VMESS|$P_TROJAN|$P_SS|$P_SSHWS)$" \
    | grep -vE '^(127\.0\.0\.1:|\[::1\]:)' || true)
  if [ -z "$exposed" ]; then _ok "zero internal ports on public interfaces"
  else _bad "PUBLIC LEAK of internal ports: $exposed"; fi
  # Nginx must own 80 and 443
  if ss -ltnH 2>/dev/null | gq -qE ':80\b'; then _ok "listener on :80"
  else _bad "no listener on :80"; fi
  if ss -ltnH 2>/dev/null | gq -qE ':443\b'; then _ok "listener on :443"
  else _bad "no listener on :443"; fi

  # ── Phase 6: Xray config hardness ──────────────────────────────────────────
  echo -e "\n${C}▸ Phase 6 — Xray config hardness${N}"
  for name in vless-ws vmess-ws trojan-ws ss-ws; do
    if jq -e --arg t "$name" \
      '.inbounds[]|select(.tag==$t)|select(.listen=="127.0.0.1")|select(.streamSettings.security=="none")' \
      "$XRAY_CFG" >/dev/null 2>&1; then
      _ok "Xray $name: localhost + security:none"
    else
      _bad "Xray $name: not locked to localhost/security:none"
    fi
  done
  # No dangerous open inbounds (API dokodemo-door on 127.0.0.1 is allowed)
  if jq -e '.inbounds[]|select((.protocol=="dokodemo-door" and .tag!="api") or .protocol=="socks" or .protocol=="http")' \
    "$XRAY_CFG" >/dev/null 2>&1; then
    _bad "dangerous inbound protocol present (dokodemo/socks/http)"
  else
    _ok "no open dokodemo/socks/http (API localhost ok)"
  fi
  _req "Xray JSON validates" validate_xray_config_file "$XRAY_CFG"
  _req "Nginx -t passes" nginx -t
  install -d -m 755 /run/sshd 2>/dev/null || true
  _req "sshd -t passes" sshd -t

  # ── Phase 7: E2E data path (all protocols) ─────────────────────────────────
  echo -e "\n${C}▸ Phase 7 — End-to-end data path (strict)${N}"
  for proto in vless vmess trojan ss; do
    if protocol_e2e_probe "$proto"; then _ok "E2E $proto data path"
    else _bad "E2E $proto data path FAILED"; fi
  done

  # ── Phase 8: SSH tunnel-only policy ────────────────────────────────────────
  echo -e "\n${C}▸ Phase 8 — SSH tunnel-only policy${N}"
  _req "hold script executable" test -x "$HOLD"
  _req "sshd drop-in exists" test -f "$SSH_DROPIN"
  if grep -q "ForceCommand $HOLD" "$SSH_DROPIN" 2>/dev/null; then
    _ok "ForceCommand locked to hold"
  else _bad "ForceCommand not locked to hold"; fi
  _req "group $SSH_GROUP exists" getent group "$SSH_GROUP"
  mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$WSP_SSH" ssh 2>/dev/null || true)
  if [[ "${R3[0]:-}" == *101* ]] && [ "${R3[2]:-}" = banner ]; then
    _ok "SSH-WS full path 101 + banner"
  else
    _bad "SSH-WS full path failed (${R3[0]:-no answer})"
  fi

  # ── Phase 9: harden profile (promoted strictness) ──────────────────────────
  echo -e "\n${C}▸ Phase 9 — Harden profile${N}"
  if [ -f /etc/sysctl.d/99-finixo-harden.conf ]; then _ok "sysctl harden file present"
  else _wrn "sysctl harden missing (run: finixo harden)"; fi
  if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | gq -q bbr; then _ok "BBR congestion control"
  else _wrn "BBR not active"; fi
  if systemctl is-active --quiet fail2ban 2>/dev/null; then _ok "fail2ban active"
  else _wrn "fail2ban inactive"; fi
  if ensure_time_sync >/dev/null 2>&1; then _ok "time/NTP synchronized"
  elif is_container; then _wrn "container clock follows host (keep host NTP accurate for VMess)"
  else _bad "clock not synchronized (breaks VMess)"; fi

  # ── Phase 10: link generation integrity ────────────────────────────────────
  echo -e "\n${C}▸ Phase 10 — Link generation integrity${N}"
  lock_profile_to_server
  if validate_client_profile_syntax; then _ok "client profile syntax"
  else _bad "client profile syntax invalid"; fi
  if validate_generated_links >/dev/null 2>&1; then _ok "generated links validate"
  else _bad "generated links validation failed"; fi
  if ss_key_ok; then _ok "Shadowsocks key/method OK"
  else _bad "Shadowsocks key/method invalid"; fi
  # Paths must all be unique
  if [ "$WSP_VLESS" != "$WSP_VMESS" ] && [ "$WSP_VLESS" != "$WSP_TROJAN" ] \
    && [ "$WSP_VLESS" != "$WSP_SS" ] && [ "$WSP_VLESS" != "$WSP_SSH" ] \
    && [ "$WSP_VMESS" != "$WSP_TROJAN" ] && [ "$WSP_VMESS" != "$WSP_SS" ] \
    && [ "$WSP_VMESS" != "$WSP_SSH" ] && [ "$WSP_TROJAN" != "$WSP_SS" ] \
    && [ "$WSP_TROJAN" != "$WSP_SSH" ] && [ "$WSP_SS" != "$WSP_SSH" ]; then
    _ok "all 5 WS paths unique"
  else
    _bad "duplicate WebSocket paths detected"
  fi

  # ── Verdict ────────────────────────────────────────────────────────────────
  echo
  echo -e "  ${W}IRON TEST RESULT${N}  ${G}pass=$passes${N}  ${R}fail=$fails${N}  ${Y}warn=$warns${N}"
  if [ "$fails" -eq 0 ]; then
    ok "IRON TEST PASSED — stack meets maximum strict criteria."
    return 0
  else
    err "IRON TEST FAILED — $fails critical failure(s). Do not expose to production."
    return "$fails"
  fi
}


# The number the user types for a menu entry (looked up by label, so text never drifts from the menu).
menu_no() {
  local i
  for i in "${!U_LB[@]}"; do
    if [ "${U_LB[i]}" = "$1" ]; then
      if ((i == ${#U_LB[@]} - 1)); then echo 0; else echo $((i + 1)); fi
      return 0
    fi
  done
  echo '?'
}

# ----------------------------------------------------------------------------
# Finixo TUI — full-screen menu: arrows / hjkl / tap+wheel / 1-20 jump
# Tab = dashboard · r = refresh · q = quit.  Actions run on the normal screen
# (inside a subshell, so a failing step can never kill the menu).
# ----------------------------------------------------------------------------
U_ACTIVE=0; U_VIEW=menu; U_SELI=0; U_BUF=""; U_MSG=""; U_OFF=0; U_AUTO=0; U_SELLINE=0
U_TMO=5; U_DIRTY=1; U_ONL_X=0; U_ONL_S=0; U_ONL_OK=0; U_LAST_FULL=0; U_QUIT=0; U_TC=0; U_W=80; U_M=0; U_COLS=80; U_ROWS=24; U_HALF=38; U_PER=2
U_CL=(); U_FL=(); U_LI=(); U_LB=(
  "Install / Reinstall" "Connection links" "TLS certificate" "Users"
  "VLESS (TLS)" "VLESS non-TLS" "VMess" "Trojan" "Shadowsocks 2022" "SSH over WebSocket"
  "Connection Control" "Client endpoint" "Restart services" "Quick self-test" "DEEP AUDIT" "IRON TEST (strict)"
  "Update Xray-core" "Repair" "Harden BBR/f2b" "Uninstall" "Exit")
U_DS=(
  "Fresh install or full reinstall (new credentials and paths)"
  "All links: VLESS, VMess, Trojan, SS2022, SSH-WS + endpoint"
  "Show / renew / replace the TLS certificate (Let's Encrypt, self-signed, own files)"
  "Users: name · online/offline · devices · entered · left · data used · expiry"
  "VLESS-WS (TLS profile): add users, list users + links — manage them in Connection Control"
  "VLESS over plain WebSocket (security=none, port 80)"
  "VMess-WS: add users, list users + links — manage them in Connection Control"
  "Trojan-WS: add users, list users + links — manage them in Connection Control"
  "Shadowsocks 2022: links, change cipher — a new key is made in Connection Control"
  "SSH over WebSocket: add / list users, connection info + payload, login banner"
  "Disable · enable · kick · renew · reset key · delete — sessions end with one short Xray restart"
  "Client endpoint (Remote / SNI / Host) — locked to this server"
  "Restart Xray, SSH bridge and Nginx, then self-test"
  "Quick self-test + real traffic through every protocol (tunnel verdict)"
  "Deep audit: 10 layers + end-to-end for each protocol"
  "Iron test: deep audit + self-test + adversarial / security probes"
  "Update Xray-core (SHA256/512 verified, atomic replace)"
  "Repair Xray, sshd, bridge, Nginx and firewall rules"
  "Harden: BBR, permissions, fail2ban, firewall, time sync"
  "Uninstall Finixo Gate (Nginx/UFW packages are kept)"
  "Leave the menu")
U_COUNT=${#U_LB[@]}

u_rgb() {   # result in U_RGB (no subshell)
  if [ "$U_TC" = 1 ]; then printf -v U_RGB '\e[38;2;%s;%s;%sm' "$1" "$2" "$3"
  else printf -v U_RGB '\e[38;5;%sm' $((16 + 36 * (($1 * 5 + 127) / 255) + 6 * (($2 * 5 + 127) / 255) + (($3 * 5 + 127) / 255))); fi
}
u_color_init() {
  # Same detection as the rest of the script: 24-bit only when the terminal announces it, 256 colours otherwise.
  # NO_COLOR keeps the layout but drops every colour (selection = reverse video).
  U_TC=0; [ "${FINIXO_CMODE:-256}" = true ] && U_TC=1
  U_RST=$'\e[0m'; U_BLD=$'\e[1m'
  u_rgb 255 80 100;  U_RED=$U_RGB; u_rgb 255 45 85;   U_ACC=$U_RGB; u_rgb 255 240 245; U_WHT=$U_RGB
  u_rgb 80 230 140;  U_GRN=$U_RGB; u_rgb 180 100 120; U_DIM=$U_RGB; u_rgb 255 190 70;  U_YEL=$U_RGB
  u_grad "F I N I X O   G A T E" 255 30 60 255 120 40; U_GTITLE=$U_G
  if [ "$U_TC" = 1 ]; then U_SEL=$'\e[48;2;160;20;45m\e[1;38;2;255;255;255m'
  else U_SEL=$'\e[48;5;124m\e[1;38;5;231m'; fi
  if [ "${FINIXO_CMODE:-256}" = none ]; then
    U_RED=""; U_ACC=""; U_WHT=""; U_GRN=""; U_DIM=""; U_YEL=""; U_SEL=$'\e[7m'
    U_GTITLE="${U_BLD}F I N I X O   G A T E${U_RST}"
  fi
}
u_grad() {   # text r1 g1 b1 r2 g2 b2  -> U_G
  local s=$1 n=${#1} i r g b c out=""
  for ((i = 0; i < n; i++)); do
    r=$(($2 + ($5 - $2) * i / (n > 1 ? n - 1 : 1)))
    g=$(($3 + ($6 - $3) * i / (n > 1 ? n - 1 : 1)))
    b=$(($4 + ($7 - $4) * i / (n > 1 ? n - 1 : 1)))
    u_rgb "$r" "$g" "$b"; out+="$U_RGB${s:i:1}"
  done
  U_G="$U_BLD$out$U_RST"
}
U_RESIZED=0
# NOTE: no `read` builtin in here — u_setdim also runs as the SIGWINCH trap, and a nested `read` cancels the timer of the
# `read -t` that the trap interrupted (the screen would then wait for a key instead of repainting).
u_setdim() {
  U_DIRTY=1; local s r c
  s=$(stty size 2>/dev/null) || s=""
  r=${s%% *}; c=${s##* }
  if [[ $r =~ ^[0-9]+$ && $c =~ ^[0-9]+$ ]] && ((r > 0 && c > 0)); then U_ROWS=$r; U_COLS=$c
  else U_ROWS=$(tput lines 2>/dev/null || echo 24); U_COLS=$(tput cols 2>/dev/null || echo 80); fi
  U_W=$((U_COLS - 2)); ((U_W > 98)) && U_W=98; ((U_W < 36)) && U_W=36
  U_M=$(((U_COLS - U_W - 2) / 2)); ((U_M < 0)) && U_M=0
  printf -v U_HL '%*s' "$U_W" ''; U_HL=${U_HL// /═}
  if ((U_W >= 60)); then U_PER=2; U_HALF=$(((U_W - 2) / 2)); else U_PER=1; U_HALF=$((U_W - 2)); fi
}
u_winch() { u_setdim; U_RESIZED=1; }   # SIGWINCH handler: new size now, u_key hands back rc 3 within 0.25 s

# ---- box primitives ---------------------------------------------------------
u_strip() { local s=$1 re=$'\e\\[[0-9;]*m'; while [[ $s =~ $re ]]; do s=${s/"${BASH_REMATCH[0]}"/}; done; U_LEN=${#s}; U_PLAIN=$s; }
u_ln()   { local x; printf -v x '%*s%s%s' "$U_M" '' "$1" "$U_RST"; U_CL+=("$x"); }
u_row()  { u_strip "$1"; local p=$((U_W - U_LEN)) c=$1
           if ((p < 0)); then c="${U_WHT}${U_PLAIN:0:U_W-1}…${U_RST}"; p=0; fi
           printf -v U_SP '%*s' "$p" ''; u_ln "${U_ACC}║${U_RST}${c}${U_RST}${U_SP}${U_ACC}║"; }
u_crow() { u_strip "$1"; local l=$(((U_W - U_LEN) / 2)); ((l < 0)) && l=0; printf -v U_CP '%*s' "$l" ''; u_row "$U_CP$1"; }
u_top()  { u_ln "${U_ACC}╔${U_HL}╗"; }
u_bot()  { u_ln "${U_ACC}╚${U_HL}╝"; }
u_sec()  { local t=" $1 " f; ((${#t} > U_W - 1)) && t=" ${1:0:U_W-4}… "
           f=$((U_W - 1 - ${#t})); ((f < 0)) && f=0; printf -v U_SP '%*s' "$f" ''; U_SP=${U_SP// /═}
           u_ln "${U_ACC}╠═${U_RST}${U_WHT}${U_BLD}${t}${U_RST}${U_ACC}${U_SP}╣"; }
u_trunc() { local v=$1 n=$2; ((n < 2)) && n=2; if ((${#v} > n)); then U_T="${v:0:n-1}…"; else U_T=$v; fi; }
u_kv()   { local l; printf -v l '%-13s' "$1"; u_trunc "$2" $((U_W - 18)); u_row " ${U_DIM}${l}${U_RST} ${U_WHT}${U_T}${U_RST}"; }
u_kvc()  { local l; printf -v l '%-13s' "$1"; u_row " ${U_DIM}${l}${U_RST} $2"; }
u_bar()  { local p=$1 w=$2 f c a b; ((p > 100)) && p=100; ((p < 0)) && p=0; f=$((p * w / 100)); c=$U_GRN
           ((p >= 70)) && c=$U_YEL; ((p >= 90)) && c=$U_RED
           printf -v a '%*s' "$f" ''; printf -v b '%*s' $((w - f)) ''; U_BAR="${c}${a// /█}${U_DIM}${b// /░}${U_RST}"; }
u_badge(){ if ((U_W < 60)); then
             if [ "$1" = 1 ]; then U_BD="${U_GRN}● ON${U_RST} "; else U_BD="${U_RED}● OFF${U_RST}"; fi
           else
             if [ "$1" = 1 ]; then U_BD="${U_GRN}● ONLINE${U_RST} "; else U_BD="${U_RED}● OFFLINE${U_RST}"; fi
           fi; }
u_chk()  { local t=$2; u_trunc "$t" $((U_W - 6)); if [ "$1" = 1 ]; then u_row " ${U_GRN}✓${U_RST} ${U_WHT}${U_T}${U_RST}"; else u_row " ${U_RED}✗${U_RST} ${U_WHT}${U_T}${U_RST}"; fi; }
u_wrapc(){ local s=$1 col=$2 n=$((U_W - 6)) i; for ((i = 0; i < ${#s}; i += n)); do u_row "    ${col}${s:i:n}${U_RST}"; done; }

u_header() {
  local tag
  u_top; u_row ""
  u_crow "$U_GTITLE"
  u_trunc "v$VERSION · VLESS · VMess · Trojan · SS2022 · SSH-WS" $((U_W - 2)); u_crow "${U_DIM}${U_T}${U_RST}"
  if [ "$U_INST" = 1 ]; then tag="${U_GRN}● LIVE${U_RST} ${U_DIM}real data from this server${U_RST}"
  else tag="${U_YEL}● NOT INSTALLED${U_RST} ${U_DIM}open 1 → Install${U_RST}"; fi
  u_crow "$tag"
  if [ "$U_INST" = 1 ]; then
    u_crow "${U_ACC}● ${U_WHT}Online now: ${U_ACC}${U_BLD}${U_ONLINE}${U_RST}  ${U_DIM}Xray ${U_ONL_X} · SSH ${U_ONL_S} · v${VERSION}${U_RST}"
    if [ "$U_ONL_OK" != 1 ]; then u_crow "${U_YEL}! Xray live counter off — run Repair ($(menu_no Repair))${U_RST}"; fi
  fi
  u_row ""
}
u_title() {   # compact boxed title used by sub-menus and action screens
  [ -n "${U_RST:-}" ] || u_color_init
  u_setdim; U_CL=()
  u_top; u_crow "$U_GTITLE  ${U_DIM}·${U_RST}  ${U_WHT}${U_BLD}$1${U_RST}"; u_bot
  printf '%s\n' "${U_CL[@]}"
}

# ---- live data ----------------------------------------------------------------
u_svc()    { systemctl is-active --quiet "$1" 2>/dev/null && echo 1 || echo 0; }
u_yes()    { "$@" >/dev/null 2>&1 && echo 1 || echo 0; }
u_listen() { ss -ltnH 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {f=1} END{exit !f}' && echo 1 || echo 0; }
u_lo()     { ss -ltnH 2>/dev/null | gq -qE "127\.0\.0\.1:$1\b" && echo 1 || echo 0; }
u_upd() {
  local cache=/run/finixo/xray-update.cache rem="" now mt=0
  [ -n "$1" ] || { U_XU=INSTALL; return; }
  [ -f "$cache" ] && rem=$(awk -F= '/^remote=/{print $2; exit}' "$cache" 2>/dev/null)
  now=$(date +%s); [ -f "$cache" ] && mt=$(stat -c %Y "$cache" 2>/dev/null || echo 0)
  if [ -z "$rem" ] || ((now - mt > 3600)); then ( xray_update_state >/dev/null 2>&1 & ) 2>/dev/null; fi
  if [ -z "$rem" ]; then U_XU=CHECKING; elif [ "$rem" = "$1" ]; then U_XU=CURRENT; else U_XU=UPDATE; fi
}
u_online_refresh() {   # cheap: Xray stats API + ps only
  local x s
  if online_stats_ready; then U_ONL_OK=1; else U_ONL_OK=0; fi
  x=$(online_xray_emails 2>/dev/null | sed '/^$/d' | wc -l)
  s=$(online_ssh_sessions 2>/dev/null | sed '/^$/d' | wc -l)
  U_ONL_X=$(( ${x:-0} )); U_ONL_S=$(( ${s:-0} )); U_ONLINE=$(( U_ONL_X + U_ONL_S ))
  U_DIRTY=1
}
# Real RAM / swap / CPU for the menu and the dashboard — read from /proc inside bash (no fork), refreshed on every tick.
# "Used" is total minus AVAILABLE: the page cache is reclaimable, so counting it as used would show a fake, scary number.
U_CPU_T0=0; U_CPU_B0=0; U_CPUP=0; U_SWP=0; U_SWT=0; U_RT=0; U_RA=0; U_RU=0; U_RP=0; U_RAMTXT=""; U_RAVAIL=""; U_SWTXT=""
u_res_refresh() {
  local k v _x tot=0 av=0 fr=0 bu=0 ca=0 swt=0 swf=0 _c cu=0 cn=0 cs=0 ci=0 cw=0 cq=0 cx=0 ct=0 tt b
  if [ -r /proc/meminfo ]; then
    while read -r k v _x; do
      case $k in
        MemTotal:) tot=$v ;; MemAvailable:) av=$v ;; MemFree:) fr=$v ;; Buffers:) bu=$v ;; Cached:) ca=$v ;;
        SwapTotal:) swt=$v ;; SwapFree:) swf=$v ;;
      esac
    done < /proc/meminfo
  fi
  [[ $tot =~ ^[0-9]+$ ]] || tot=0
  ((av > 0)) || av=$((fr + bu + ca))
  ((av > tot)) && av=$tot
  U_RT=$((tot / 1024)); U_RA=$((av / 1024)); U_RU=$((U_RT - U_RA))
  U_RP=0; ((tot > 0)) && U_RP=$(( (tot - av) * 100 / tot ))
  fmt_kib $((tot - av)); U_RAMTXT="$FMT_F / "; fmt_kib "$tot"; U_RAMTXT+=$FMT_F
  fmt_kib "$av"; U_RAVAIL=$FMT_F
  U_SWT=$swt; U_SWP=0; ((swt > 0)) && U_SWP=$(( (swt - swf) * 100 / swt ))
  fmt_kib $((swt - swf)); U_SWTXT="$FMT_F / "; fmt_kib "$swt"; U_SWTXT+=$FMT_F
  if read -r _c cu cn cs ci cw cq cx ct _ < /proc/stat 2>/dev/null; then
    tt=$((cu + cn + cs + ci + cw + cq + cx + ct)); b=$((tt - ci - cw))
    if ((U_CPU_T0 > 0 && tt > U_CPU_T0)); then
      U_CPUP=$(( (b - U_CPU_B0) * 100 / (tt - U_CPU_T0) )); ((U_CPUP < 0)) && U_CPUP=0; ((U_CPUP > 100)) && U_CPUP=100
    fi
    U_CPU_T0=$tt; U_CPU_B0=$b
  fi
  U_DIRTY=1
}
u_load() {
  load_conf
  U_INST=0; is_installed 2>/dev/null && U_INST=1
  U_ADDR=${SERVER_ADDR:-not set}; U_IP=${SERVER_IP:-}; [ -n "$U_IP" ] || U_IP=$(cat "$IP_FILE" 2>/dev/null || echo n/a)
  local -a _st=()
  mapfile -t _st < <(systemctl is-active nginx xray finixo-ssh-ws fail2ban 2>/dev/null)
  U_S_NGX=0; U_S_XRAY=0; U_S_SSH=0; U_S_F2B=0
  [ "${_st[0]:-}" = active ] && U_S_NGX=1;  [ "${_st[1]:-}" = active ] && U_S_XRAY=1
  [ "${_st[2]:-}" = active ] && U_S_SSH=1;  [ "${_st[3]:-}" = active ] && U_S_F2B=1
  U_S_UFW=0; grep -qs '^ENABLED=yes' /etc/ufw/ufw.conf && U_S_UFW=1
  U_S_BBR=0; grep -qs bbr /proc/sys/net/ipv4/tcp_congestion_control && U_S_BBR=1
  U_CERT_OK=0; [[ $(cert_badge_plain 2>/dev/null) == ONLINE* ]] && U_CERT_OK=1
  U_CKIND=$(cert_kind_short 2>/dev/null || echo none); U_CDAYS=$(cert_days_left 2>/dev/null || echo n/a)
  U_XV=$(xray_local_ver 2>/dev/null || true); u_upd "$U_XV"; U_XV=${U_XV:-none}
  if [ "$U_INST" = 1 ]; then
    U_N_VLESS=$(count_xray_clients vless-ws); U_N_VMESS=$(count_xray_clients vmess-ws)
    U_N_TROJAN=$(count_xray_clients trojan-ws); U_N_SS=$(count_xray_clients ss-ws)
    U_N_SSH=$(count_ssh_tunnel_users)
  else U_N_VLESS=0; U_N_VMESS=0; U_N_TROJAN=0; U_N_SS=0; U_N_SSH=0; fi
  U_N_TOTAL=$((U_N_VLESS + U_N_VMESS + U_N_TROJAN + U_N_SS + U_N_SSH))
  # Throttle expiry purge to once per 60s so the TUI stays snappy
  now_ts=$(date +%s)
  if [ $(( now_ts - ${U_LAST_PURGE:-0} )) -ge 60 ]; then
    purge_expired_clients 2>/dev/null || true
    U_LAST_PURGE=$now_ts
  fi
  u_online_refresh
  U_LAST_FULL=$(date +%s)
  U_OS=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}")
  u_res_refresh
  read -r U_DU U_DT U_DP < <(df -h / 2>/dev/null | awk 'NR==2{print $3,$2,$5}'); U_DU=${U_DU:-?}; U_DT=${U_DT:-?}; U_DP=${U_DP%\%}; U_DP=${U_DP:-0}
  U_UP=$(uptime -p 2>/dev/null | sed 's/^up //'); U_UP=${U_UP:-n/a}
  U_LOAD=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo n/a); U_KERN=$(uname -r 2>/dev/null); U_NCPU=$(nproc 2>/dev/null || echo 1)
  U_TLSMODE=$(tls_mode_text 2>/dev/null || echo auto)
  [ "$U_VIEW" = dash ] && u_dash_probe
  U_DIRTY=1
}
u_has() { grep -qE "$2" <<< "$1" && echo 1 || echo 0; }
u_dash_probe() {   # heavier checks: only while the dashboard is open
  local o; o=$(ss -ltnH 2>/dev/null); U_D_SSHP=$(ssh_port 2>/dev/null || echo 22)
  U_D_80=$(u_has "$o" '[:.]80[[:space:]]'); U_D_443=$(u_has "$o" '[:.]443[[:space:]]')
  U_D_SSH=$(u_has "$o" "[:.]${U_D_SSHP}[[:space:]]")
  U_D_XR=1; local p; for p in $P_VLESS $P_VMESS $P_TROJAN $P_SS; do [ "$(u_has "$o" "127\.0\.0\.1:$p[[:space:]]")" = 1 ] || U_D_XR=0; done
  U_D_BR=$(u_has "$o" "127\.0\.0\.1:$P_SSHWS[[:space:]]")
  U_D_SYS=0; [ -f /etc/sysctl.d/99-finixo-harden.conf ] && U_D_SYS=1
  U_D_NTP=$(u_yes bash -c 'timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi yes')
  U_D_GRP=$(u_yes getent group "${SSH_GROUP:-tunnel-only}")
  U_D_UNIT=$(u_yes grep -qs NoNewPrivileges /etc/systemd/system/xray.service)
  U_D_NFT=$(u_yes nft list table inet finixo)
  U_D_CB=$(u_yes systemctl is-enabled certbot.timer)
}

# ---- menu ---------------------------------------------------------------------
u_cell() {
  local i=$1 num mark=" " plain pad nn lb maxl
  ((i == U_COUNT - 1)) && num=0 || num=$((i + 1))
  ((i == U_SELI)) && mark="▸"
  printf -v nn '%2s' "$num"
  lb=${U_LB[i]}; maxl=$((U_HALF - 8)); ((${#lb} > maxl)) && lb="${lb:0:maxl-1}…"
  plain=" $mark $nn  $lb"
  printf -v pad '%*s' $((U_HALF - ${#plain} > 0 ? U_HALF - ${#plain} : 0)) ''
  if ((i == U_SELI)); then U_CELL="${U_SEL}${plain}${pad}${U_RST}"
  else U_CELL=" ${mark} ${U_ACC}${nn}${U_RST}  ${U_WHT}${lb}${U_RST}${pad}"; fi
}
u_pairs() {
  local i a b ln
  for ((i = $1; i <= $2; i += U_PER)); do
    ln=${#U_CL[@]}
    u_cell "$i"; a=$U_CELL; b=""; U_LI[i]="$ln:L"
    if ((U_PER == 2 && i + 1 <= $2)); then u_cell $((i + 1)); b=$U_CELL; U_LI[i+1]="$ln:R"; fi
    if ((i == U_SELI || (U_PER == 2 && i + 1 == U_SELI))); then U_SELLINE=$ln; fi
    u_row " ${a}${b}"
  done
}
u_foot_hint() {
  if ((U_COLS >= 98)); then U_FH="↑↓←→/hjkl move · ⏎ open · 1-20 jump · tap/wheel · Tab dash · r refresh · q quit"
  elif ((U_COLS >= 66)); then U_FH="↑↓←→ move · ⏎ open · 1-20 jump · Tab dash · q quit"
  else U_FH="↑↓ move · ⏎ open · q quit"; fi
}
u_build_menu() {
  U_CL=(); U_SELLINE=0; U_LI=()
  u_header
  u_sec "STATUS"
  u_bar "$U_RP" 10; local ram=$U_BAR cpuc=$U_GRN; u_trunc "$U_UP" 18
  ((U_CPUP >= 70)) && cpuc=$U_YEL; ((U_CPUP >= 90)) && cpuc=$U_RED
  if ((U_W >= 96)); then u_row " ${U_ACC}${U_IP}${U_RST} ${U_DIM}│${U_RST} ${U_WHT}RAM${U_RST} $ram ${U_WHT}${U_RP}%${U_RST} ${U_DIM}${U_RAMTXT}${U_RST} ${U_DIM}│${U_RST} ${U_WHT}CPU${U_RST} ${cpuc}${U_CPUP}%${U_RST} ${U_DIM}│ up ${U_T}${U_RST}"
  elif ((U_W >= 74)); then u_row " ${U_ACC}${U_IP}${U_RST} ${U_DIM}│${U_RST} ${U_WHT}RAM${U_RST} $ram ${U_WHT}${U_RP}%${U_RST} ${U_DIM}│${U_RST} ${U_WHT}CPU${U_RST} ${cpuc}${U_CPUP}%${U_RST} ${U_DIM}│ up ${U_T}${U_RST}"
  elif ((U_W >= 50)); then u_row " ${U_ACC}${U_IP}${U_RST} ${U_DIM}│${U_RST} ${U_WHT}RAM${U_RST} $ram ${U_WHT}${U_RP}%${U_RST} ${U_DIM}│${U_RST} ${U_WHT}CPU${U_RST} ${cpuc}${U_CPUP}%${U_RST}"
  else u_row " ${U_ACC}${U_IP}${U_RST} ${U_DIM}│${U_RST} ${U_WHT}RAM${U_RST} $ram ${U_WHT}${U_RP}%${U_RST}"; fi
  u_badge "$U_S_NGX"; local b1=$U_BD; u_badge "$U_S_XRAY"; local b2=$U_BD; u_badge "$U_S_SSH"; local b3=$U_BD
  u_row " ${U_WHT}Nginx${U_RST} $b1 ${U_WHT}Xray${U_RST} $b2 ${U_WHT}SSH-WS${U_RST} $b3"
  u_badge "$U_CERT_OK"
  u_row " ${U_WHT}Cert${U_RST}  $U_BD ${U_DIM}${U_CKIND} · ${U_CDAYS} left${U_RST}"
  local xc=$U_YEL; [ "$U_XU" = CURRENT ] && xc=$U_GRN
  u_row " ${U_WHT}Core${U_RST}  Xray $U_XV  ${xc}[$U_XU]${U_RST}"
  if ((U_W >= 60)); then
    u_row " ${U_WHT}VLESS${U_RST} $U_N_VLESS  ${U_WHT}VMess${U_RST} $U_N_VMESS  ${U_WHT}Trojan${U_RST} $U_N_TROJAN  ${U_WHT}SS${U_RST} $U_N_SS  ${U_WHT}SSH${U_RST} $U_N_SSH  ${U_DIM}│ total${U_RST} ${U_ACC}$U_N_TOTAL${U_RST}"
  else
    u_row " ${U_WHT}VLESS${U_RST} $U_N_VLESS  ${U_WHT}VMess${U_RST} $U_N_VMESS  ${U_WHT}Trojan${U_RST} $U_N_TROJAN"
    u_row " ${U_WHT}SS${U_RST} $U_N_SS  ${U_WHT}SSH${U_RST} $U_N_SSH  ${U_DIM}│ total${U_RST} ${U_ACC}$U_N_TOTAL${U_RST}"
  fi
  u_sec "SETUP";     u_pairs 0 3
  u_sec "PROTOCOLS"; u_pairs 4 10
  u_sec "SYSTEM";    u_pairs 11 $((U_COUNT - 1))
  u_sec "ABOUT THIS ENTRY"
  u_trunc "${U_DS[U_SELI]}" $((U_W - 5)); u_row " ${U_YEL}▸${U_RST} ${U_WHT}${U_T}${U_RST}"
  u_bot
  u_foot_hint
  local msg="   ${U_ACC}›${U_RST} ${U_WHT}${U_BUF}${U_RST}${U_DIM}_${U_RST}"
  [ -n "$U_MSG" ] && msg="   ${U_YEL}! ${U_MSG}${U_RST}"
  U_FL=("   ${U_DIM}${U_FH}${U_RST}" "$msg")
}
u_build_dash() {
  U_CL=(); local s
  u_header
  u_sec "SERVER"
  u_kv "OS" "$U_OS"; u_kv "Address" "$U_ADDR  ($U_IP)"; u_kv "Kernel" "$U_KERN · $U_NCPU cores · load $U_LOAD"
  u_bar "$U_RP" 24; u_kvc "RAM" "$U_BAR ${U_WHT}${U_RP}%${U_RST} ${U_DIM}${U_RAMTXT}${U_RST}"
  u_kvc "Available" "${U_WHT}${U_RAVAIL}${U_RST} ${U_DIM}free for programs (the cache is not counted as used)${U_RST}"
  if ((U_SWT > 0)); then u_bar "$U_SWP" 24; u_kvc "Swap" "$U_BAR ${U_WHT}${U_SWP}%${U_RST} ${U_DIM}${U_SWTXT}${U_RST}"; fi
  u_bar "$U_CPUP" 24; u_kvc "CPU" "$U_BAR ${U_WHT}${U_CPUP}%${U_RST}"
  u_bar "$U_DP" 24; u_kvc "Disk /" "$U_BAR ${U_WHT}${U_DP}%${U_RST} ${U_DIM}${U_DU}/${U_DT}${U_RST}"
  u_kv "Uptime" "$U_UP"
  u_sec "SERVICES"
  u_badge "$U_S_NGX";  u_kvc "Nginx"  "$U_BD ${U_DIM}public :80 :443 (decoy site + WS routes)${U_RST}"
  u_badge "$U_S_XRAY"; u_kvc "Xray"   "$U_BD ${U_DIM}127.0.0.1:$P_VLESS-$P_SS (security:none)${U_RST}"
  u_badge "$U_S_SSH";  u_kvc "SSH-WS" "$U_BD ${U_DIM}127.0.0.1:$P_SSHWS → sshd (tunnel-only)${U_RST}"
  u_badge "$U_CERT_OK"; u_kvc "Certificate" "$U_BD ${U_DIM}${U_CKIND} · ${U_CDAYS} left${U_RST}"
  local xc=$U_YEL; [ "$U_XU" = CURRENT ] && xc=$U_GRN
  u_kvc "Xray core" "${U_WHT}${U_XV}${U_RST}  ${xc}[$U_XU]${U_RST}"
  u_sec "ACCOUNTS"
  for s in "VLESS:$U_N_VLESS" "VMess:$U_N_VMESS" "Trojan:$U_N_TROJAN" "SS2022:$U_N_SS" "SSH:$U_N_SSH"; do
    u_bar $((${s#*:} * 10)) 20; u_kvc "${s%%:*}" "$U_BAR ${U_WHT}${s#*:}${U_RST}"
  done
  u_kvc "Total" "${U_ACC}${U_BLD}$U_N_TOTAL${U_RST} ${U_DIM}accounts${U_RST}"
  u_kvc "Online now" "${U_ACC}${U_BLD}$U_ONLINE${U_RST} ${U_DIM}users · Xray $U_ONL_X · SSH $U_ONL_S${U_RST}"
  u_sec "CLIENT ENDPOINT"
  u_kv "Remote Proxy" "${REMOTE_PROXY:-n/a}"; u_kv "TLS SNI" "${CLIENT_SNI:-n/a}"; u_kv "WS Host" "${CLIENT_HOST:-n/a}"; u_kv "Security" "$U_TLSMODE"
  u_sec "WEBSOCKET PATHS"
  u_kv "VLESS" "${WSP_VLESS:-n/a}"; u_kv "VMess" "${WSP_VMESS:-n/a}"; u_kv "Trojan" "${WSP_TROJAN:-n/a}"
  u_kv "Shadowsocks" "${WSP_SS:-n/a}"; u_kv "SSH-WS" "${WSP_SSH:-n/a}"
  u_sec "PORTS"
  u_chk "$U_D_80"  "80/tcp   Nginx (decoy + ACME + WS)"
  u_chk "$U_D_443" "443/tcp  Nginx TLS"
  u_chk "$U_D_SSH" "${U_D_SSHP}/tcp   sshd (public SSH)"
  u_chk "$U_D_XR"  "$P_VLESS vless · $P_VMESS vmess · $P_TROJAN trojan · $P_SS ss  (127.0.0.1 only)"
  u_chk "$U_D_BR"  "$P_SSHWS ssh-ws bridge (127.0.0.1 only)"
  u_sec "SECURITY"
  u_chk "$U_S_UFW" "UFW: deny incoming, allow SSH / 80 / 443"
  u_chk "$U_S_F2B" "fail2ban protecting sshd"
  u_chk "$U_S_BBR" "BBR + fq congestion control"
  u_chk "$U_D_SYS" "sysctl harden profile"
  u_chk "$U_D_NTP" "Time sync — required for VMess"
  u_chk "$U_D_GRP" "Group ${SSH_GROUP:-tunnel-only} · ForceCommand hold"
  u_chk "$U_D_UNIT" "Xray unit hardened (NoNewPrivileges, ProtectSystem)"
  u_chk "$U_D_NFT" "nftables guard: tunnel users blocked from private nets"
  u_chk "$U_D_CB" "certbot.timer auto-renew"
  u_bot
  U_FL=("   ${U_DIM}↑↓ PgUp PgDn scroll · Tab menu · r refresh · q quit${U_RST}")
}
u_paint() {
  local avail=$((U_ROWS - ${#U_FL[@]})) total=${#U_CL[@]} i j buf
  ((avail < 5)) && avail=5
  if ((U_AUTO)); then
    ((U_SELLINE < U_OFF)) && U_OFF=$((U_SELLINE - 2))
    ((U_SELLINE >= U_OFF + avail)) && U_OFF=$((U_SELLINE - avail + 3))
    ((U_SELLINE < avail - 1)) && U_OFF=0
  fi
  ((U_OFF > total - avail)) && U_OFF=$((total - avail)); ((U_OFF < 0)) && U_OFF=0
  local last=$((U_OFF + avail)); ((last > total)) && last=$total
  if ((total > avail)); then U_POS="lines $((U_OFF + 1))-${last} of ${total}"; else U_POS=""; fi
  buf=$'\e[H'
  for ((i = U_OFF; i < U_OFF + avail && i < total; i++)); do buf+="${U_CL[i]}"$'\e[K\n'; done
  buf+=$'\e[J'
  for ((j = 0; j < ${#U_FL[@]}; j++)); do ((j > 0)) && buf+=$'\n'; buf+="${U_FL[j]//@POS@/$U_POS}"; done
  printf '%s' "$buf"
}

# ---- input --------------------------------------------------------------------
# Waits for one key. Returns 0 key in U_K · 1 input closed · 2 timeout (U_TMO seconds, may be fractional) · 3 window resized.
# bash keeps waiting inside `read -t` when a trapped signal (SIGWINCH) arrives, so the wait is cut into 0.25 s slices.
u_key() {
  local rc c seq intro left a b slice
  U_K=""
  if ((U_RESIZED)); then U_RESIZED=0; return 3; fi
  a=${U_TMO%%.*}; b=000
  [[ $U_TMO == *.* ]] && { b=${U_TMO#*.}000; b=${b:0:3}; }
  [[ $a =~ ^[0-9]*$ ]] || a=5; a=${a:-0}
  left=$((10#$a * 1000 + 10#$b)); ((left < 20)) && left=20
  while :; do
    slice=$left; ((slice > 250)) && slice=250
    printf -v c '0.%03d' "$slice"
    IFS= read -rsn1 -t "$c" c; rc=$?
    if ((rc == 0)); then break; fi
    ((rc <= 128)) && return 1          # EOF / error: the terminal is gone
    if ((U_RESIZED)); then U_RESIZED=0; return 3; fi
    left=$((left - slice)); ((left <= 0)) && return 2
  done
  if [[ $c == $'\e' ]]; then
    if read -rsn1 -t 0.15 c; then
      if [[ $c == '[' || $c == 'O' ]]; then
        intro=$c; seq=""
        while read -rsn1 -t 0.15 c; do seq+=$c; [[ $c =~ [A-Za-z~] ]] && break; done
        if [[ $intro == O ]]; then U_K=$'\eO'"$seq"; else U_K=$'\e['"$seq"; fi
      else U_K=$'\e'$c; fi
    else U_K=$'\e'; fi
  else U_K=$c; fi
  return 0
}
u_jump() {
  local n
  [[ $U_BUF =~ ^[0-9]+$ ]] || return 0
  n=$((10#$U_BUF))
  if ((n == 0)); then U_SELI=$((U_COUNT - 1))
  elif ((n >= 1 && n <= U_COUNT - 1)); then U_SELI=$((n - 1))
  else U_BUF=${U_BUF: -1}; u_jump; fi
}
u_move() {   # dir: up/down/left/right
  U_BUF=""
  case $1 in
    up)    ((U_SELI >= U_PER)) && U_SELI=$((U_SELI - U_PER)) ;;
    down)  ((U_SELI + U_PER <= U_COUNT - 1)) && U_SELI=$((U_SELI + U_PER)) ;;
    left)  ((U_SELI > 0)) && U_SELI=$((U_SELI - 1)) ;;
    right) ((U_SELI < U_COUNT - 1)) && U_SELI=$((U_SELI + 1)) ;;
  esac
}
u_mouse() {
  local body=${1#$'\e[<'} fin=${1: -1} b x y line it side i
  body=${body%[Mm]}
  IFS=';' read -r b x y <<< "$body"
  [[ $b =~ ^[0-9]+$ && $x =~ ^[0-9]+$ && $y =~ ^[0-9]+$ ]] || return 0
  case $b in
    64) if [ "$U_VIEW" = menu ]; then u_move up; else U_OFF=$((U_OFF - 3)); fi ;;
    65) if [ "$U_VIEW" = menu ]; then u_move down; else U_OFF=$((U_OFF + 3)); fi ;;
    0)  [ "$fin" = M ] && [ "$U_VIEW" = menu ] || return 0
        line=$((U_OFF + y - 1))
        for ((i = 0; i < U_COUNT; i++)); do
          it=${U_LI[i]:-}; [ -n "$it" ] || continue
          [ "${it%%:*}" = "$line" ] || continue
          side=${it##*:}
          if ((U_PER == 2)); then
            if ((x > U_M + 1 + U_HALF)); then [ "$side" = R ] || continue; else [ "$side" = L ] || continue; fi
          fi
          U_SELI=$i; U_BUF=""; u_open "$i"; return 0
        done ;;
  esac
}

# ---- actions ------------------------------------------------------------------
u_enter() { printf '\e[?1049h\e[?25l\e[?1000h\e[?1006h'; U_ACTIVE=1; }
u_leave() { printf '\e[?1006l\e[?1000l\e[?25h\e[?1049l%s' "$U_RST"; U_ACTIVE=0; }
u_pause() { printf '\n  %spress any key to return to the menu%s' "$U_DIM" "$U_RST"; IFS= read -rsn1 _ || true; }
u_exec()  {
  trap ':' INT
  ( trap cleanup EXIT; trap 'exit 130' INT TERM; "$@" )
  local rc=$?
  trap 'exit 130' INT
  return "$rc"
}
u_run()  { local t=$1; shift; u_leave; clear 2>/dev/null || true; u_title "$t"; u_exec "$@"; u_pause; u_enter; }
u_runm() { local t=$1; shift; u_leave; clear 2>/dev/null || true; u_title "$t"; u_exec "$@"; u_enter; }
u_need() { [ "$U_INST" = 1 ] && return 0; U_MSG="Not installed yet — open 1 (Install) first"; return 1; }
u_endpoint() {
  load_conf; client_profile_summary; echo
  info "The client endpoint is locked to this server: links always use ${SERVER_ADDR}:443."
}
u_selftest() { self_test; echo; tunnel_verdict; }
# ── Small formatting helpers (bash only, no fork; the answer is left in FMT_F) ──────────────────────────────
fmt_bytes() {   # bytes -> "1.23 GiB"
  local b=${1:-0} i x
  [[ $b =~ ^[0-9]+$ ]] || b=0
  if ((b < 1024)); then FMT_F="$b B"; return 0; fi
  x=$((b * 100 / 1024)); i=1
  while ((x >= 102400 && i < 4)); do x=$((x / 1024)); i=$((i + 1)); done
  local -a U=(B KiB MiB GiB TiB)
  if ((x >= 10000)); then FMT_F="$((x / 100)) ${U[i]}"
  elif ((x >= 1000)); then printf -v FMT_F '%d.%d %s' $((x / 100)) $((x % 100 / 10)) "${U[i]}"
  else printf -v FMT_F '%d.%02d %s' $((x / 100)) $((x % 100)) "${U[i]}"; fi
}
fmt_kib() { fmt_bytes $(( ${1:-0} * 1024 )); }
fmt_dur() {   # seconds -> "3d 4h" / "5h 12m" / "42m 10s" / "9s"
  local t=${1:-0}
  ((t < 0)) && t=0
  if ((t >= 86400)); then FMT_F="$((t / 86400))d $((t % 86400 / 3600))h"
  elif ((t >= 3600)); then FMT_F="$((t / 3600))h $((t % 3600 / 60))m"
  elif ((t >= 60)); then FMT_F="$((t / 60))m $((t % 60))s"
  else FMT_F="${t}s"; fi
}

u_open() {
  case $1 in
    0)  u_runm "INSTALL / REINSTALL" do_install ;;
    1)  u_need && u_run "CONNECTION LINKS" show_all_links ;;
    2)  u_need && u_runm "TLS CERTIFICATE" cert_menu ;;
    3)  u_need && u_run "USERS" users_report ;;
    4)  u_need && u_runm "VLESS · WebSocket" proto_menu vless-ws VLESS ;;
    5)  u_need && u_run "VLESS NON-TLS" show_vless_notls_links ;;
    6)  u_need && u_runm "VMESS · WebSocket" proto_menu vmess-ws VMess ;;
    7)  u_need && u_runm "TROJAN · WebSocket" proto_menu trojan-ws Trojan ;;
    8)  u_need && u_runm "SHADOWSOCKS 2022" ss_menu ;;
    9)  u_need && u_runm "SSH · WebSocket" ssh_menu ;;
    10) u_need && u_runm "CONNECTION CONTROL" connection_control_menu ;;
    11) u_need && u_run "CLIENT ENDPOINT" u_endpoint ;;
    12) u_need && u_run "RESTART SERVICES" restart_all ;;
    13) u_need && u_run "QUICK SELF-TEST" u_selftest ;;
    14) u_need && u_run "DEEP AUDIT v$VERSION" deep_audit ;;
    15) u_need && u_run "IRON TEST (STRICT)" iron_test ;;
    16) u_run "UPDATE XRAY-CORE" do_update_xray ;;
    17) u_need && u_run "REPAIR" do_repair ;;
    18) u_need && u_run "HARDEN" do_harden ;;
    19) u_run "UNINSTALL" do_uninstall ;;
    *)  U_QUIT=1 ;;
  esac
  u_load
}
u_loop() {
  local rc
  while ((U_QUIT == 0)); do
    if [ "$U_VIEW" = menu ]; then u_build_menu; U_AUTO=1
    else U_AUTO=0; if ((U_DIRTY)); then u_build_dash; U_DIRTY=0; fi; fi
    u_paint
    u_key; rc=$?
    if ((rc == 1)); then break; fi
    if ((rc == 3)); then U_DIRTY=1; continue; fi
    if ((rc == 2)); then
      u_setdim; u_res_refresh
      if (( $(date +%s) - U_LAST_FULL >= 30 )); then u_load; else u_online_refresh; fi
      continue
    fi
    U_MSG=""
    case $U_K in
      $'\e['A) if [ "$U_VIEW" = menu ]; then u_move up; else U_OFF=$((U_OFF - 1)); fi ;;
      $'\e['B) if [ "$U_VIEW" = menu ]; then u_move down; else U_OFF=$((U_OFF + 1)); fi ;;
      $'\e['C) [ "$U_VIEW" = menu ] && u_move right ;;
      $'\e['D) [ "$U_VIEW" = menu ] && u_move left ;;
      $'\e['5~) U_OFF=$((U_OFF - 10)) ;;
      $'\e['6~) U_OFF=$((U_OFF + 10)) ;;
      $'\e['H|$'\e['1~) U_SELI=0; U_OFF=0 ;;
      $'\e['F|$'\e['4~) U_SELI=$((U_COUNT - 1)) ;;
      $'\e[<'*) u_mouse "$U_K" ;;
      $'\t'|i|I) if [ "$U_VIEW" = menu ]; then U_VIEW=dash; u_dash_probe; else U_VIEW=menu; fi; U_OFF=0; U_BUF=""; U_DIRTY=1 ;;
      '') [ "$U_VIEW" = menu ] && { u_open "$U_SELI"; U_BUF=""; } ;;
      [0-9]) if [ "$U_VIEW" = menu ]; then U_BUF+=$U_K; u_jump; fi ;;
      k) [ "$U_VIEW" = menu ] && u_move up ;;
      j) [ "$U_VIEW" = menu ] && u_move down ;;
      h) [ "$U_VIEW" = menu ] && u_move left ;;
      l) [ "$U_VIEW" = menu ] && u_move right ;;
      r|R) u_load; U_BUF="" ;;
      q|Q) U_QUIT=1 ;;
      $'\x7f'|$'\b') U_BUF="" ;;
    esac
  done
}
u_exit_trap() { ((U_ACTIVE)) && u_leave; cleanup; }
u_main() {
  if [ ! -t 0 ] || [ ! -t 1 ]; then do_status; return 0; fi
  u_color_init; u_setdim; u_load
  U_QUIT=0; U_VIEW=menu; U_SELI=0; U_BUF=""
  [ "$U_INST" = 1 ] || U_SELI=0
  trap u_exit_trap EXIT
  trap 'exit 130' INT TERM
  trap u_winch WINCH
  u_enter
  u_loop
  u_leave; clear 2>/dev/null || true
  trap cleanup EXIT
  trap - WINCH
}
main_menu() {
  need_root; self_install >/dev/null 2>&1 || true
  if is_installed 2>/dev/null && ! { online_stats_ready && xray_tuning_ready; }; then
    warn "Xray needs a one-time runtime upgrade: the exact online counter + a steadier connection policy"
    warn "(idle tunnels survive 30 min, 8 s handshake). One restart of ~1 s; clients reconnect by themselves."
    if confirm "Apply it now?"; then
      ensure_xray_runtime || warn "Could not apply it — try: finixo repair"
    fi
  fi
  u_main
}

# ----------------------------------------------------------------------------
# Tunnel verdict — real traffic through every protocol, with retries
# ----------------------------------------------------------------------------
tunnel_verdict() {
  load_conf
  local good=0 bad=0 s proto name pth out t rc total
  local -a R3
  echo -e "\n${W}══ TUNNEL VERDICT — real traffic through every protocol ══${N}\n"
  for s in nginx xray finixo-ssh-ws; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then ok "service $s is active"; good=$((good+1))
    else err "service $s is NOT active"; journal_hint "$s" 2>/dev/null || true; bad=$((bad+1)); fi
  done
  if [ "${FINIXO_EDGE:-haproxy}" = haproxy ]; then
    systemctl is-active --quiet haproxy || { err "haproxy is not active (edge)"; bad=1; }
  fi
  if ss -ltnH 2>/dev/null | awk '$4 ~ /:443$/ {f=1} END{exit !f}'; then ok "port 443 is listening"; good=$((good+1)); else err "nothing listens on 443"; bad=$((bad+1)); fi
  for name in "VLESS:$WSP_VLESS" "VMess:$WSP_VMESS" "Trojan:$WSP_TROJAN" "Shadowsocks:$WSP_SS"; do
    pth=${name#*:}; name=${name%%:*}; rc=1
    for t in 1 2 3; do
      mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$pth" 2>/dev/null)
      if [[ "${R3[0]:-}" == *101* ]]; then rc=0; break; fi; sleep 2
    done
    if ((rc == 0)); then ok "$name  TLS + WebSocket upgrade on :443 → 101"; good=$((good+1))
    else err "$name  WebSocket upgrade failed (${R3[0]:-no answer})"; bad=$((bad+1)); fi
  done
  for proto in vless vmess trojan ss; do
    rc=1; out=""
    for t in 1 2 3; do
      out=$(protocol_e2e_probe "$proto" 2>&1) && { rc=0; break; } || rc=$?
      if [ "$rc" = 2 ]; then break; fi
      sleep 2
    done
    printf '%s\n' "$out"
    if [ "$rc" = 0 ]; then good=$((good+1))
    elif [ "$rc" = 2 ]; then info "$proto E2E skipped (no users) — not counted as pass"
    else bad=$((bad+1)); fi
  done
  rc=1
  for t in 1 2 3; do
    mapfile -t R3 < <(ws_probe 127.0.0.1 443 1 "${CLIENT_SNI:-localhost}" "${CLIENT_HOST:-localhost}" "$WSP_SSH" ssh 2>/dev/null)
    if [[ "${R3[0]:-}" == *101* ]] && [ "${R3[2]:-}" = banner ]; then rc=0; break; fi; sleep 2
  done
  if ((rc == 0)); then ok "SSH-WS  upgrade 101 + OpenSSH banner (Nginx → bridge → sshd)"; good=$((good+1))
  else err "SSH-WS  failed (${R3[0]:-no answer})"; bad=$((bad+1)); fi
  local hdr b404
  hdr=$(curl -sk -m 5 -I -H "Host: ${CLIENT_HOST:-localhost}" https://127.0.0.1/ 2>/dev/null)
  b404=$(curl -sk -m 5 -H "Host: ${CLIENT_HOST:-localhost}" "https://127.0.0.1/zz-$RANDOM" 2>/dev/null)
  if grep -qi '^server:.*nginx' <<< "$hdr"; then warn "Server header still says nginx (headers-more module unavailable) — run Repair ($(menu_no Repair)) with internet access"
  else ok "Stealth: Server header hidden"; good=$((good+1)); fi
  if grep -qi 'nginx' <<< "$b404"; then warn "Stealth: 404 page mentions nginx"; else ok "Stealth: generic 404 page (no nginx text)"; good=$((good+1)); fi
  total=$((good + bad))
  echo
  if ((bad == 0)); then
    echo -e "  ${G}${B}✓ TUNNEL OK${N}  ${W}$good/$total checks passed — active checks succeeded (skipped = no users yet).${N}"
    info "If a phone client still cannot connect: open ports 80/443 in the cloud provider firewall."
    return 0
  fi
  echo -e "  ${R}${B}✗ TUNNEL PROBLEM${N}  ${W}$bad of $total checks failed.${N}"
  info "Try: Repair (menu $(menu_no Repair)) then Quick self-test. Logs: journalctl -u xray -n 40 --no-pager"
  return 1
}

usage() {
  echo "Finixo Gate $VERSION"
  echo "Usage: $0 [menu|install|links|online|devices|watchdog|test|tunnel|deep-test|strict-test|harden|repair|profile|cert|uninstall|status|version]"
  echo "       devices [all]|limit N|off   devices per account (estimate) · the limit only marks accounts, it never cuts anyone"
  echo "       watchdog [status|run|on|off]   self-healing: restarts Xray / SSH bridge / Nginx only when one HANGS"
}

do_status() {
  need_root; load_conf
  printf '%sFinixo Gate %s%s\n' "$W" "$VERSION" "$N"
  printf 'address : %s\n' "${SERVER_ADDR:-not set}"
  printf 'profile : remote=%s sni=%s host=%s (%s)\n' \
    "${REMOTE_PROXY:-}" "${CLIENT_SNI:-}" "${CLIENT_HOST:-}" "$(tls_mode_text 2>/dev/null || echo n/a)"
  printf 'nginx   : %s\n' "$(svc_badge_plain nginx)"
  printf 'xray    : %s\n' "$(svc_badge_plain xray)"
  printf 'ssh-ws  : %s\n' "$(svc_badge_plain finixo-ssh-ws)"
  printf 'haproxy : %s (edge=%s)\n' "$(svc_badge_plain haproxy)" "${FINIXO_EDGE:-haproxy}"
  printf 'cert    : %s remaining\n' "$(cert_days_left)"
  if [ -n "${WSP_VLESS:-}" ]; then
    printf 'paths   : vless=%s vmess=%s trojan=%s ss=%s ssh=%s\n' \
      "$WSP_VLESS" "$WSP_VMESS" "$WSP_TROJAN" "$WSP_SS" "$WSP_SSH"
  fi
  if is_installed 2>/dev/null; then
    printf 'online  : %s users now (Xray=%s SSH=%s)%s\n' \
      "$(count_online_connections)" "$(online_xray_emails 2>/dev/null | sed '/^$/d' | wc -l)" \
      "$(online_ssh_sessions 2>/dev/null | sed '/^$/d' | wc -l)" \
      "$(online_stats_ready || echo '  [Xray counter off: run finixo repair]')"
    if [ -e "$CONF_DIR/watchdog.off" ]; then printf 'watchdog: off\n'
    elif systemctl is-active --quiet finixo-watchdog.timer 2>/dev/null; then printf 'watchdog: on (checks every minute)\n'
    else printf 'watchdog: not scheduled — run: finixo repair\n'; fi
    printf 'accounts: VLESS=%s VMess=%s Trojan=%s SS=%s SSH=%s\n' \
      "$(count_xray_clients vless-ws)" "$(count_xray_clients vmess-ws)" \
      "$(count_xray_clients trojan-ws)" "$(count_xray_clients ss-ws)" \
      "$(count_ssh_tunnel_users)"
  fi
  if [ -x "$XRAY_BIN" ]; then xray_ver_line; fi
}

# Allows `FINIXO_SOURCE_ONLY=1 source finixo.sh` for testing the functions.
if [ "${FINIXO_SOURCE_ONLY:-0}" = 1 ]; then return 0 2>/dev/null || exit 0; fi

case "${1:-}" in
  install) do_install ;;
  links) need_root; is_installed || die "Not installed."; show_all_links ;;
  test) need_root; is_installed || die "Not installed."; self_test ;;
  tunnel) need_root; is_installed || die "Not installed."; tunnel_verdict ;;
  deep-test|deep) need_root; is_installed || die "Not installed."; deep_audit ;;
  strict-test|strict|iron) need_root; is_installed || die "Not installed."; iron_test ;;
  harden) need_root; is_installed || die "Not installed."; do_harden ;;
  repair) do_repair ;;
  migrate-ssh-path|ssh-path) need_root; is_installed || die "Not installed."; migrate_ssh_path "${2:-/ssh-ws}" ;;
  purge-expired|purge) purge_expired_clients ;;
  online|who) need_root; is_installed || die "Not installed."; show_online ;;
  conn-control|sessions|connections) need_root; is_installed || die "Not installed."; connection_control_menu ;;
  devices|dev) need_root; is_installed || die "Not installed."; shift; devices_cli "$@" ;;
  watchdog|wd|guard) shift; wd_cli "$@" ;;
  emergency-admin|root-access|admin-access|show-admin) show_admin_access ;;
  profile) need_root; is_installed || die "Not installed."; info "Remote/SNI/Host editing has been removed. Links always use this server address."; do_status; pause ;;
  cert) need_root; is_installed || die "Not installed."; cert_menu ;;
  status) do_status ;;
  version|-V|--version) echo "Finixo Gate $VERSION" ;;
  uninstall) do_uninstall ;;
  -h|--help|help) usage ;;
  menu|"") need_root; if is_installed; then main_menu; else do_install; is_installed && main_menu; fi ;;
  *) usage; exit 1 ;;
esac
