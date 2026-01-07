.PHONY: filter-api generate-client clean

# Variables
API_JSON := api.json
ALLOWED_ENDPOINTS := allowed-endpoints.json
FILTERED_API_JSON := api-filtered.json
OPENAPI_CFG := openapi-cfg.yaml

# Filter API JSON to only include allowed endpoints
filter-api:
	@echo "Filtering API JSON using allowed endpoints..."
	@jq --slurpfile allowed $(ALLOWED_ENDPOINTS) \
		'.paths |= with_entries(select(.key as $$k | $$allowed[0] | index($$k)))' \
		$(API_JSON) > $(FILTERED_API_JSON)
	@echo "Filtered API JSON written to $(FILTERED_API_JSON)"

# Generate OpenAPI client using oapi-codegen
generate-client: filter-api
	@echo "Generating OpenAPI client..."
	@go tool oapi-codegen -config $(OPENAPI_CFG) $(FILTERED_API_JSON)
	@echo "Client generated successfully"

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -f $(FILTERED_API_JSON)
	@echo "Clean complete"
