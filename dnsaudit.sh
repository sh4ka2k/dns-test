#!/usr/bin/env bash
# =============================================================================
# DNSAudit CLI - DNS security scanning powered by dnsaudit.io
# Author: Esteban Borges - https://dnsaudit.io
# =============================================================================

set -euo pipefail

readonly VERSION="1.0.0"
readonly BASE_URL="https://dnsaudit.io/api"

# ─── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"
  RED="\033[31m"; YELLOW="\033[33m"; GREEN="\033[32m"; CYAN="\033[36m"
else
  BOLD=""; DIM=""; RESET=""
  RED=""; YELLOW=""; GREEN=""; CYAN=""
fi

# ─── Helpers ─────────────────────────────────────────────────────────────────
die()  { echo -e "${RED}Error:${RESET} $*" >&2; exit 1; }
info() { echo -e "$*"; }

require_cmd() {
  command -v "$1" &>/dev/null || die "'$1' is required but not installed."
}

require_api_key() {
  [[ -n "${API_KEY:-}" ]] || die "No API key set. Export DNSAUDIT_API_KEY or use --api-key."
}

# Perform a GET request; prints response body and exits non-zero on HTTP errors.
api_get() {
  local path="$1"; shift
  local url="${BASE_URL}${path}"
  local tmp
  tmp=$(mktemp)

  local http_code
  http_code=$(curl -s -o "$tmp" -w "%{http_code}" \
    -H "X-API-Key: ${API_KEY}" \
    "$url" "$@")

  local body
  body=$(cat "$tmp"); rm -f "$tmp"

  case "$http_code" in
    200) echo "$body"; return 0 ;;
    401) die "Invalid or missing API key (401 Unauthorized)." ;;
    403) die "API access not enabled for your account. Contact dnsaudit.io support (403 Forbidden)." ;;
    404) die "No scan results found for this domain (404 Not Found)." ;;
    429)
      local msg retry reset
      msg=$(echo "$body"  | jq -r '.message // "Rate limit exceeded."' 2>/dev/null)
      retry=$(echo "$body" | jq -r '.retryAfter  // empty'             2>/dev/null || true)
      reset=$(echo "$body" | jq -r '.resetDate   // empty'             2>/dev/null || true)
      local hint=""
      [[ -n "$retry" ]] && hint+="  Retry after ${retry}s."
      [[ -n "$reset" ]] && hint+="  Daily limit resets on ${reset}."
      die "Rate limit: ${msg}${hint}"
      ;;
    5*)  die "Server error (HTTP ${http_code}). Try again later." ;;
    *)   die "Unexpected HTTP ${http_code}: $(echo "$body" | jq -r '.error // .' 2>/dev/null || echo "$body")" ;;
  esac
}

# Download binary (PDF) to a file path.
api_get_binary() {
  local path="$1" outfile="$2"
  local url="${BASE_URL}${path}"
  local http_code
  http_code=$(curl -s -o "$outfile" -w "%{http_code}" \
    -H "X-API-Key: ${API_KEY}" \
    "${url}?format=detailed")

  case "$http_code" in
    200) return 0 ;;
    401) die "Invalid or missing API key (401 Unauthorized)." ;;
    403) die "API access not enabled for your account (403 Forbidden)." ;;
    404) die "No scan results found for this domain (404 Not Found)." ;;
    429) die "Rate limit exceeded. Wait before retrying." ;;
    *)   die "Unexpected HTTP ${http_code} while downloading PDF." ;;
  esac
}

# ─── Grade colour ─────────────────────────────────────────────────────────────
grade_colour() {
  case "$1" in
    A+|A|A-) echo -e "${GREEN}${BOLD}$1${RESET}" ;;
    B+|B|B-) echo -e "${CYAN}${BOLD}$1${RESET}"  ;;
    C+|C|C-) echo -e "${YELLOW}${BOLD}$1${RESET}";;
    *)        echo -e "${RED}${BOLD}$1${RESET}"   ;;
  esac
}

status_icon() {
  case "${1,,}" in
    pass)    echo -e "${GREEN}✔${RESET}" ;;
    warning) echo -e "${YELLOW}⚠${RESET}" ;;
    fail|error) echo -e "${RED}✘${RESET}" ;;
    *)       echo "·" ;;
  esac
}

status_tag() {
  case "${1,,}" in
    pass)    echo -e "${GREEN}[PASS]${RESET}"    ;;
    warning) echo -e "${YELLOW}[WARNING]${RESET}" ;;
    fail)    echo -e "${RED}[FAIL]${RESET}"      ;;
    error)   echo -e "${RED}[ERROR]${RESET}"     ;;
    *)       echo "[$1]" ;;
  esac
}

# ─── Commands ─────────────────────────────────────────────────────────────────

cmd_scan() {
  local domain="" output_json=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)      output_json=true ;;
      --no-colo*r) BOLD=""; DIM=""; RESET=""; RED=""; YELLOW=""; GREEN=""; CYAN="" ;;
      --api-key)   shift; API_KEY="$1" ;;
      --api-key=*) API_KEY="${1#*=}" ;;
      -*)          die "Unknown option: $1" ;;
      *)           domain="$1" ;;
    esac
    shift
  done

  [[ -n "$domain" ]] || die "Usage: dnsaudit scan <domain> [--json] [--api-key KEY]"
  require_api_key
  require_cmd curl
  require_cmd jq

  local result
  result=$(api_get "/v1/scan?domain=${domain}")

  if $output_json; then
    echo "$result" | jq .
    return
  fi

  local scan_date score grade critical warnings passed
  scan_date=$(echo "$result" | jq -r '.scanDate // ""')
  score=$(echo "$result"     | jq -r '.securityScore // "?"')
  grade=$(echo "$result"     | jq -r '.grade // "?"')
  critical=$(echo "$result"  | jq -r '.summary.criticalIssues // 0')
  warnings=$(echo "$result"  | jq -r '.summary.warnings // 0')
  passed=$(echo "$result"    | jq -r '.summary.passed // 0')

  echo
  echo -e "${BOLD}  DNS Security Audit: ${domain}${RESET}"
  echo -e "${DIM}  ${scan_date}${RESET}"
  echo
  echo -e "  Score: ${BOLD}${score}${RESET}/100   Grade: $(grade_colour "$grade")"
  echo
  echo -e "  ${GREEN}${passed} passed${RESET}   ${YELLOW}${warnings} warnings${RESET}   ${RED}${critical} critical${RESET}"
  echo
  echo -e "${BOLD}  Check Results${RESET}"
  echo -e "${DIM}  ────────────────────────────────────────${RESET}"

  # Iterate over each check key
  while IFS= read -r check; do
    local status details record icon tag
    status=$(echo "$result"  | jq -r --arg k "$check" '.results[$k].status  // ""')
    details=$(echo "$result" | jq -r --arg k "$check" '.results[$k].details // ""')
    record=$(echo "$result"  | jq -r --arg k "$check" '.results[$k].record  // ""')

    icon=$(status_icon "$status")
    tag=$(status_tag "$status")
    local label
    label=$(printf "%-10s" "${check^^}")

    echo -e "  ${icon} ${label} ${tag} ${details}"
    [[ -n "$record" ]] && echo -e "${DIM}             ${record}${RESET}"
  done < <(echo "$result" | jq -r '.results | keys[]' 2>/dev/null)

  echo
}

# ─────────────────────────────────────────────────────────────────────────────

cmd_export() {
  local domain="" fmt="json" outfile=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --format)    shift; fmt="$1" ;;
      --format=*)  fmt="${1#*=}" ;;
      -o|--output) shift; outfile="$1" ;;
      --output=*)  outfile="${1#*=}" ;;
      --api-key)   shift; API_KEY="$1" ;;
      --api-key=*) API_KEY="${1#*=}" ;;
      -*)          die "Unknown option: $1" ;;
      *)           domain="$1" ;;
    esac
    shift
  done

  [[ -n "$domain" ]] || die "Usage: dnsaudit export <domain> [--format json|pdf] [-o FILE]"
  require_api_key
  require_cmd curl

  case "${fmt,,}" in
    pdf)
      outfile="${outfile:-${domain}-report.pdf}"
      api_get_binary "/export/pdf/${domain}" "$outfile"
      info "PDF report saved to ${outfile}"
      ;;
    json)
      require_cmd jq
      local result
      result=$(api_get "/export/json/${domain}")
      if [[ -n "$outfile" ]]; then
        echo "$result" | jq . > "$outfile"
        info "JSON export saved to ${outfile}"
      else
        echo "$result" | jq .
      fi
      ;;
    *)
      die "Unknown format '${fmt}'. Use json or pdf."
      ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────

cmd_history() {
  local limit=10 output_json=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --limit)     shift; limit="$1" ;;
      --limit=*)   limit="${1#*=}" ;;
      --json)      output_json=true ;;
      --no-colo*r) BOLD=""; DIM=""; RESET=""; RED=""; YELLOW=""; GREEN=""; CYAN="" ;;
      --api-key)   shift; API_KEY="$1" ;;
      --api-key=*) API_KEY="${1#*=}" ;;
      -*)          die "Unknown option: $1" ;;
    esac
    shift
  done

  require_api_key
  require_cmd curl
  require_cmd jq

  local result
  result=$(api_get "/v1/scan-history?limit=${limit}")

  if $output_json; then
    echo "$result" | jq .
    return
  fi

  local total
  total=$(echo "$result" | jq -r '.total // 0')

  echo
  echo -e "${BOLD}  Scan History  (${total} total)${RESET}"
  echo -e "${DIM}  ─────────────────────────────────────────────────────────${RESET}"
  printf "${DIM}  %-35s %6s  %-5s  %s${RESET}\n" "Domain" "Score" "Grade" "Date"
  echo -e "${DIM}  ─────────────────────────────────────────────────────────${RESET}"

  while IFS= read -r entry; do
    local d score grade date gc
    d=$(echo "$entry"     | jq -r '.domain        // ""')
    score=$(echo "$entry" | jq -r '.securityScore // "?"')
    grade=$(echo "$entry" | jq -r '.grade         // "?"')
    date=$(echo "$entry"  | jq -r '.scanDate      // ""' | cut -c1-10)
    gc=$(grade_colour "$grade")
    printf "  %-35s %6s  ${gc}%-5s${RESET}  %s\n" "$d" "$score" "$grade" "$date"
  done < <(echo "$result" | jq -c '.scans[]' 2>/dev/null)

  echo
}

# ─── Usage ────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF

${BOLD}DNSAudit CLI${RESET} v${VERSION} — DNS security scanning powered by dnsaudit.io
${DIM}Author: Esteban Borges — https://dnsaudit.io${RESET}

${BOLD}USAGE${RESET}
  dnsaudit <command> [options]

${BOLD}COMMANDS${RESET}
  scan <domain>         Run a full DNS security scan (26+ checks)
  export <domain>       Export scan results as JSON or PDF
  history               Show recent scan history

${BOLD}OPTIONS${RESET}
  --api-key KEY         API key (overrides \$DNSAUDIT_API_KEY)
  --json                Output raw JSON
  --no-colour           Disable ANSI colours
  --limit N             Number of history entries (default: 10, max: 100)
  --format json|pdf     Export format (default: json)
  -o, --output FILE     Save output to FILE

${BOLD}EXAMPLES${RESET}
  export DNSAUDIT_API_KEY=dns_xxxx

  dnsaudit scan example.com
  dnsaudit scan example.com --json
  dnsaudit export example.com --format pdf -o report.pdf
  dnsaudit history --limit 25

${BOLD}AUTHENTICATION${RESET}
  Set \$DNSAUDIT_API_KEY or pass --api-key with every command.

${BOLD}RATE LIMITS${RESET}
  20 scans / day   ·   10 requests / minute burst

EOF
}

# ─── Entry point ──────────────────────────────────────────────────────────────

# Resolve API key: env var (can be overridden per-command by --api-key)
API_KEY="${DNSAUDIT_API_KEY:-}"

if [[ $# -eq 0 ]]; then
  usage; exit 0
fi

case "$1" in
  scan)    shift; cmd_scan    "$@" ;;
  export)  shift; cmd_export  "$@" ;;
  history) shift; cmd_history "$@" ;;
  -v|--version) echo "dnsaudit ${VERSION}"; exit 0 ;;
  -h|--help|help) usage; exit 0 ;;
  *) die "Unknown command '$1'. Run 'dnsaudit --help' for usage." ;;
esac
