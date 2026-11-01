SHELL := /bin/bash

.PHONY: up down clean setup info

up:
	@[ -f .env ] || { echo "Missing .env. Run: cp .env.example .env"; exit 1; }
	@set -a; . ./.env; set +a; \
	profiles=""; \
	[ "$$ENABLE_POSTGRES"      = "true" ] && profiles="$$profiles,postgres"       || true; \
	[ "$$ENABLE_MYSQL"         = "true" ] && profiles="$$profiles,mysql"          || true; \
	[ "$$ENABLE_MSSQL"         = "true" ] && profiles="$$profiles,mssql"          || true; \
	[ "$$ENABLE_MONGODB"       = "true" ] && profiles="$$profiles,mongodb"        || true; \
	[ "$$ENABLE_REDIS"         = "true" ] && profiles="$$profiles,redis"          || true; \
	[ "$$ENABLE_REDIS_NOAUTH"  = "true" ] && profiles="$$profiles,redis-noauth"   || true; \
	[ "$$ENABLE_SSH_PASSWORD"  = "true" ] && profiles="$$profiles,ssh-password"   || true; \
	[ "$$ENABLE_SSH_KEY"       = "true" ] && profiles="$$profiles,ssh-key"        || true; \
	profiles="$${profiles#,}"; \
	if [ -z "$$profiles" ]; then echo "No resources enabled in .env. Flip some ENABLE_* flags to true."; exit 1; fi; \
	echo "Bringing up: $$profiles"; \
	COMPOSE_PROFILES="$$profiles" docker compose up --build -d --wait
	@./setup.sh --print-info-only
	@read -p "Register in Infisical now? [y/N] " yn; \
	if [ "$$yn" = "y" ] || [ "$$yn" = "Y" ] || [ "$$yn" = "yes" ]; then ./setup.sh; else echo "Skipped. Run 'make setup' later to register."; fi

down:
	@docker compose --profile postgres --profile mysql --profile mssql --profile mongodb \
	                --profile redis --profile redis-noauth \
	                --profile ssh-password --profile ssh-key down

clean:
	@docker compose --profile postgres --profile mysql --profile mssql --profile mongodb \
	                --profile redis --profile redis-noauth \
	                --profile ssh-password --profile ssh-key down -v --rmi local --remove-orphans
	@for v in pam_pgdata pam_mysqldata pam_mssqldata pam_mongodata \
	          pam_redisdata pam_redisnoauthdata pam_sshkeydata; do \
	  docker volume rm "$$(basename $$PWD)_$$v" 2>/dev/null || true; \
	done
	@echo "clean: containers, images, and volumes removed."

setup:
	@./setup.sh

info:
	@./setup.sh --print-info-only
