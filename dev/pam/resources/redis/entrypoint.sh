#!/bin/sh
set -e

# Seed once in the background after the server is up. The .seeded marker key
# lives in the same persistent volume so this is a no-op on subsequent starts.
(
  for _ in $(seq 1 60); do
    if redis-cli --user infisical -a Infisical@123 PING >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done

  if [ "$(redis-cli --user infisical -a Infisical@123 GET .seeded)" != "1" ]; then
    echo "Seeding redis..."
    redis-cli --user infisical -a Infisical@123 < /docker-entrypoint-initdb.d/seed.redis
    redis-cli --user infisical -a Infisical@123 SET .seeded 1
    echo "Redis seed complete."
  fi
) &

exec redis-server --aclfile /etc/redis/users.acl
