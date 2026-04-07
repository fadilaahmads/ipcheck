# Load .env file if it exists
-include .env

# Priority: Manual DB_CONN override > IPCHECK_DB_URL from .env
DB_URL := $(if $(DB_CONN),$(DB_CONN),$(IPCHECK_DB_URL))

build:
	go build --ldflags "-s -w" -o ipcheck main.go

clean:
	rm ipcheck

migrate:
	@if [ -z "$(DB_URL)" ]; then \
		echo "Error: Database connection string not found."; \
		echo "Set IPCHECK_DB_URL in your .env file or pass DB_CONN='postgres://...'"; \
		exit 1; \
	fi
	psql "$(DB_URL)" -f internal/repositories/db-schemas/schema.sql
