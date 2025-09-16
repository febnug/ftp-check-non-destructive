#!/usr/bin/env bash
# ftp_check_non_destructive.sh
# Safe, non-destructive checks for FTP service. Saves outputs in ./pentest_ftp/results/<host>/
# USAGE: ./ftp_check_non_destructive.sh ftp.mypantero.com

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <host> [port]"
  exit 1
fi

HOST="$1"
PORT="${2:-21}"
OUTDIR="pentest_ftp/results/${HOST}"
mkdir -p "${OUTDIR}"

echo "[*] Output dir: ${OUTDIR}"
echo "[*] Started at $(date)" > "${OUTDIR}/run_info.txt"
echo "host=${HOST}" >> "${OUTDIR}/run_info.txt"
echo "port=${PORT}" >> "${OUTDIR}/run_info.txt"

# 1) Basic TCP banner grab (you already did this with nc)
echo "[*] Banner grab (nc) ..."
( echo "TIME: $(date)"; nc -v -w 5 "${HOST}" "${PORT}" 2>&1 ) > "${OUTDIR}/banner_nc.txt" || true

# 2) nmap: service/version + safe NSE scripts
echo "[*] Running nmap - service/version + ftp NSE scripts (safe list)..."
# safe NSE list: ftp-syst (system), ftp-anon (anonymous), ftp-bounce (bounce test), ssl-enum-ciphers (TLS ciphers)
nmap -Pn -sV -p "${PORT}" --script=ftp-syst,ftp-anon,ftp-bounce,ssl-enum-ciphers -oA "${OUTDIR}/nmap_ftp" "${HOST}"

# 3) Check anonymous login (non-destructive)
echo "[*] Checking anonymous login with curl and ftp client (non-destructive) ..."
# curl listing (some servers support MLSD; this will not upload anything)
curl --connect-timeout 8 --max-time 20 -I "ftp://${HOST}:${PORT}/" --user anonymous:anonymous@ 2> "${OUTDIR}/curl_ftp_err.txt" > "${OUTDIR}/curl_ftp_head.txt" || true

# Try with lftp (if installed) to LIST root dir; quit immediately
if command -v lftp >/dev/null 2>&1; then
  echo "[*] Using lftp to try LIST as anonymous (non-destructive) ..."
  # -e 'cls -l; quit' will list but not download or upload
  lftp -u anonymous,anonymous@ -p "${PORT}" -e "cls -l; quit" "ftp://${HOST}" > "${OUTDIR}/lftp_anon_list.txt" 2> "${OUTDIR}/lftp_anon_err.txt" || true
else
  echo "[*] lftp not installed; skipping lftp anonymous listing. Install with: sudo apt install lftp" > "${OUTDIR}/lftp_missing.txt"
fi

# 4) Check TLS / STARTTLS (explicit TLS on port 21)
echo "[*] Checking STARTTLS (FTP) with openssl s_client -starttls ftp ..."
# will print cert chain and negotiated protocol/cipher
( echo "TIME: $(date)"; echo | openssl s_client -connect "${HOST}:${PORT}" -starttls ftp -showcerts 2>&1 ) > "${OUTDIR}/openssl_starttls_ftp.txt" || true

# 5) Check implicit FTPS (port 990) if open
echo "[*] Checking implicit FTPS (port 990) ..."
( echo "TIME: $(date)"; echo | openssl s_client -connect "${HOST}:990" -showcerts 2>&1 ) > "${OUTDIR}/openssl_implicit_990.txt" || true

# 6) Quick CVE / version pointer (manual)
echo "[*] Extract version info from banner + nmap output..."
# Extract banner text and nmap service/version lines for manual CVE lookup
grep -i "proftpd" -i "${OUTDIR}/banner_nc.txt" > "${OUTDIR}/proftpd_banner_grep.txt" || true
grep -i "proftpd" "${OUTDIR}/nmap_ftp.nmap" > "${OUTDIR}/proftpd_nmap_grep.txt" || true
# Also save full nmap xml for parsing later
echo "[*] Done. Inspect files in ${OUTDIR}."

echo "[*] Completed at $(date)" >> "${OUTDIR}/run_info.txt"
echo "[*] All outputs saved under ${OUTDIR}"
