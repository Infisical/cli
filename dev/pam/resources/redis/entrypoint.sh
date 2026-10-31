#!/bin/sh
set -e

# Build redis-cli auth flags only if both creds are set; redis-noauth supplies
# neither and runs unauthenticated.
CLI_AUTH=""
if [ -n "${REDIS_AUTH_USER:-}" ] && [ -n "${REDIS_AUTH_PASSWORD:-}" ]; then
  CLI_AUTH="--user $REDIS_AUTH_USER -a $REDIS_AUTH_PASSWORD"
fi

# Seed once, in the background, after the server is up. The .seeded marker key
# persists in the same volume so subsequent starts skip the seed.
(
  for _ in $(seq 1 60); do
    if redis-cli $CLI_AUTH PING >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done

  if [ "$(redis-cli $CLI_AUTH GET .seeded)" != "1" ]; then
    echo "Seeding redis..."
    redis-cli $CLI_AUTH < /docker-entrypoint-initdb.d/seed.redis
    redis-cli $CLI_AUTH SET .seeded 1
    echo "Redis seed complete."
  fi
) &

exec redis-server ${REDIS_SERVER_ARGS:-}
