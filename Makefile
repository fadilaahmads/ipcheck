build:
	go build --ldflags "-s -w" -o ipcheck main.go

clean:
	rm ipcheck

migrate:
	@if [ -z "$(DB_CONN)" ]; then \
		echo "Error: DB_CONN is not set. Use: make migrate DB_CONN='postgres://...'"; \
		exit 1; \
	fi
	psql "$(DB_CONN)" -f internal/repositories/db-schemas/schema.sql
