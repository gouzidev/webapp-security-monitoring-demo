.PHONY: run down logs clean rebuild

# start everything
run:
	@echo "starting security demo..."
	@docker compose -f deployment/docker-compose.yml up --build -d
	@sleep 3
	@echo "\ndone! access at http://localhost:8080"
	@echo "login: admin/admin"
	@echo "\nattacker logs: http://localhost:9090/logs"

# stop containers
down:
	@docker compose -f deployment/docker-compose.yml down

# view logs
logs:
	@docker compose -f deployment/docker-compose.yml logs -f

# view attacker logs
attacker:
	@docker compose -f deployment/docker-compose.yml logs attacker

# clear logs only
clear-logs:
	@docker exec security-monitor sh -c "rm -f /tmp/security_logs.txt /var/log/waf.log" 2>/dev/null || true
	@docker exec attacker-server sh -c "rm -f /tmp/stolen.log" 2>/dev/null || true
	@echo "logs cleared"

# clean everything
clean:
	@docker compose -f deployment/docker-compose.yml down -v
	@docker system prune -f

# rebuild from scratch
rebuild: clean run
