#!/usr/bin/env bash
# Периметр сайта: заголовки, TLS, редиректы, куки, известные утечки файлов.
# Только чтение: GET/HEAD и один TLS-хендшейк. Никакого перебора путей и нагрузки.
#
#   bash scan-web.sh https://example.com
#
# Владелец должен быть ваш. Скрипт не сканирует чужие адреса.
set -uo pipefail

HOST="${1:-}"
if [ -z "$HOST" ]; then
  echo "использование: bash scan-web.sh https://host" >&2
  exit 2
fi
HOST="${HOST%/}"

# Разбор хоста и порта для корректной работы с кастомными портами (например, https://example.com:8443)
HOST_NO_PROTO="$(printf '%s' "$HOST" | sed -E 's#^https?://##; s#/.*$##')"
if [[ "$HOST_NO_PROTO" =~ :([0-9]+)$ ]]; then
  TLS_HOST="${HOST_NO_PROTO%:*}"
  TLS_PORT="${BASH_REMATCH[1]}"
else
  TLS_HOST="$HOST_NO_PROTO"
  TLS_PORT="443"
fi
HOSTNAME="$TLS_HOST"
fail=0

note() { printf '%-6s %s\n' "$1" "$2"; }
bad()  { note "FAIL" "$1"; fail=1; }
ok()   { note "ok" "$1"; }

# Кроссплатформенный запуск с таймаутом (macOS не имеет timeout из коробки)
run_with_timeout() {
  local secs="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$secs" "$@"
  else
    "$@"
  fi
}

echo "== 1. доступность =="
code="$(curl -s -o /dev/null -m 15 -w '%{http_code}' "$HOST/")"
case "$code" in
  200) ok "главная 200" ;;
  301|302|307|308) ok "главная отвечает редиректом $code" ;;
  *) bad "главная отвечает $code" ;;
esac

echo "== 2. редирект с http =="
plain="http://$HOSTNAME/"
code="$(curl -s -o /dev/null -m 15 -w '%{http_code}' "$plain")"
loc="$(curl -s -o /dev/null -m 15 -w '%{redirect_url}' "$plain")"
case "$code" in
  301|302|307|308) ok "http → $code ${loc:-без Location}" ;;
  *) bad "http отвечает $code вместо редиректа" ;;
esac

echo "== 3. security-заголовки =="
headers="$(curl -sI -m 15 "$HOST/")"
printf '%s' "$headers" | grep -qi 'strict-transport-security' && ok "HSTS есть" || bad "HSTS нет"
printf '%s' "$headers" | grep -qi 'x-content-type-options' && ok "nosniff есть" || bad "X-Content-Type-Options нет"
printf '%s' "$headers" | grep -qi 'x-frame-options\|frame-ancestors' && ok "защита от фреймов есть" || bad "X-Frame-Options/CSP frame-ancestors нет"
printf '%s' "$headers" | grep -qi 'content-security-policy' && ok "CSP есть" || note "P3" "CSP нет (вводить в Report-Only)"
printf '%s' "$headers" | grep -qi 'referrer-policy' && ok "Referrer-Policy есть" || note "P3" "Referrer-Policy нет"
printf '%s' "$headers" | grep -qi 'server:' && note "info" "раскрывает Server: $(printf '%s' "$headers" | grep -i '^server:' | head -1)"

echo "== 4. куки =="
if printf '%s' "$headers" | grep -qi '^set-cookie:'; then
  # Process substitution, чтобы bad() выставлял fail=1 в основном шелле
  while read -r line; do
    printf '%s' "$line" | grep -qi 'secure' && ok "кука с Secure: ${line:0:40}…" || bad "кука без Secure: ${line:0:60}…"
    printf '%s' "$line" | grep -qi 'httponly' && ok "кука с HttpOnly: ${line:0:40}…" || note "WARN" "кука без HttpOnly: ${line:0:60}…"
    printf '%s' "$line" | grep -qi 'samesite' && ok "кука с SameSite: ${line:0:40}…" || note "P3" "кука без SameSite: ${line:0:60}…"
  done < <(printf '%s\n' "$headers" | grep -i '^set-cookie:')
else
  note "info" "куки на этом ответе не ставятся"
fi

echo "== 5. TLS =="
tls="$(echo | run_with_timeout 20 openssl s_client -connect "$TLS_HOST:$TLS_PORT" -servername "$TLS_HOST" 2>/dev/null)"
printf '%s' "$tls" | grep -q "Protocol  : TLSv1.3" && ok "TLS 1.3 доступен" || note "info" "TLS 1.3 не подтверждён"
exp="$(printf '%s' "$tls" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
[ -n "$exp" ] && ok "сертификат до: $exp" || bad "не удалось прочитать сертификат"
printf '%s' "$tls" | grep -qi "verify return code: 0" && ok "цепочка проверена" || bad "проблема с цепочкой сертификатов"

echo "== 6. известные утечки файлов =="
for path in "/.env" "/.git/config" "/backup.zip" "/db.sqlite3" "/.DS_Store" "/server-status" "/static/../.env"; do
  # Проверяем код ответа и Content-Type для защиты от ложных срабатываний в SPA
  res="$(curl -s -o /dev/null -m 10 -w '%{http_code}|%{content_type}' "$HOST$path")"
  code="${res%%|*}"
  ctype="${res#*|}"
  case "$code" in
    200|206)
      if printf '%s' "$ctype" | grep -qi 'text/html'; then
        body="$(curl -s -m 10 "$HOST$path" | head -n 5)"
        if [ "$path" = "/.git/config" ] && printf '%s' "$body" | grep -q '\[core\]'; then
          bad "$path отдаётся ($code, $ctype)"
        elif [ "$path" = "/.env" ] && printf '%s' "$body" | grep -qE '^[A-Z0-9_]+=.+'; then
          bad "$path отдаётся ($code, $ctype)"
        else
          note "info" "$path вернул $code ($ctype), похоже на SPA fallback index.html"
        fi
      else
        bad "$path отдаётся ($code, $ctype)"
      fi
      ;;
    401|403) note "warn" "$path закрыт, но лучше 404 ($code)" ;;
    *) ok "$path → $code" ;;
  esac
done

echo "== 7. админка и служебные пути (информационно) =="
for path in "/admin/" "/admin/login/" "/health/" "/metrics" "/api/docs"; do
  code="$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$HOST$path")"
  note "info" "$path → $code"
done

echo
[ "$fail" -eq 0 ] && echo "периметр: проверки пройдены" || echo "периметр: есть находки, см. FAIL выше"
exit "$fail"
