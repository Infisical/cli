.PHONY: generate-code api.json

# Generate OpenAPI client using oapi-codegen
generate-code:
	@echo "Generating OpenAPI client..."
	@go generate
	@echo "Client generated successfully"

# Fetch API docs and format with jq
api.json:
	@echo "Fetching API docs..."
	@set -o pipefail && curl -f http://localhost:4000/api/docs/json | jq . > api.json.tmp && mv api.json.tmp api.json
	@echo "API docs saved to api.json"
