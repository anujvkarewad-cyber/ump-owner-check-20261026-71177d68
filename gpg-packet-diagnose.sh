#!/usr/bin/env bash
# Read-only GPG packet/agent diagnostic for the owner's Ubuntu recovery VM.
# No passphrase, no decryption, no restore, no production connection, no file mutation.
set -u
EXPECTED_SHA256="${EXPECTED_SHA256:-d1fa7225118741fa6a6817825c1d9b09d6910eafba84edee93e371b6ec00048c}"
SEARCH_ROOT="${SEARCH_ROOT:-$HOME}"
REPORT="${REPORT:-$HOME/gpg-packet-diagnose.txt}"

log() { printf '%s\n' "$*" | tee -a "$REPORT"; }
: > "$REPORT"
log "GPG_READ_ONLY_DIAGNOSTIC_START"
log "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "host_kernel=$(uname -srm)"

log "gpg_version=$(gpg --version 2>/dev/null | head -1 || true)"
log "gpg_libgcrypt=$(gpg --version 2>/dev/null | sed -n '2p' || true)"
log "gpg_homedir=$(gpgconf --list-dirs homedir 2>/dev/null || true)"
log "agent_version=$(timeout 10s gpg-connect-agent 'getinfo version' /bye 2>/dev/null | tr '\n' ' ' || true)"
log "agent_processes=$(pgrep -a gpg-agent 2>/dev/null | tr '\n' ';' || true)"

log "gpg_conf_selected_lines:"
grep -HE 'pinentry-mode|no-symkey-cache|use-agent|cipher-algo|s2k' "$HOME/.gnupg/gpg.conf" "$HOME/.gnupg/gpg-agent.conf" 2>/dev/null | sed -E 's/(passphrase|pin)[^ ]*=[^ ]*/\1[redacted]/Ig' | tee -a "$REPORT" || true

log "locating_exact_hash_archive"
archive=""
while IFS= read -r line; do
  hash=${line%% *}
  path=${line#*  }
  if [ "$(printf '%s' "$hash" | tr 'A-F' 'a-f')" = "$EXPECTED_SHA256" ]; then
    archive="$path"
    break
  fi
done < <(find "$SEARCH_ROOT" -type f \( -name 'ujjwal_pathak.archive.gz.gpg' -o -name 'backup.gpg' -o -name '*.gpg' \) -print0 2>/dev/null | xargs -0 -r sha256sum 2>/dev/null)

if [ -z "$archive" ]; then
  log "STATUS=STOP_EXACT_HASH_ARCHIVE_NOT_FOUND"
  log "expected_sha256=$EXPECTED_SHA256"
  log "DIAGNOSTIC_DONE_NO_DECRYPTION"
  exit 2
fi

safe_path=${archive/#$HOME/\~}
log "archive_path=$safe_path"
log "archive_bytes=$(stat -c '%s' "$archive" 2>/dev/null || printf 'unknown')"
log "archive_sha256=$(sha256sum "$archive" | awk '{print $1}')"
log "packet_summary_with_list_only:"
timeout 20s gpg --batch --no-tty --list-only --list-packets "$archive" 2>&1 \
  | grep -E 'gpg:|symkey enc packet|encrypted data packet|aead|cipher|s2k|hash|mdc_method|tag 20|AEAD|version' \
  | sed -E 's/^[[:space:]]*salt[[:space:]].*/    salt [omitted]/I' \
  | head -40 | tee -a "$REPORT" || true

log "STATUS=DIAGNOSTIC_DONE_NO_DECRYPTION"
log "report=$REPORT"
log "share_only_this_sanitized_report;_never_share_archive_or_passphrase"
