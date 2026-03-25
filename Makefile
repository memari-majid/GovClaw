BINARY      := defenseclaw
GATEWAY     := defenseclaw-gateway
VERSION     := 0.2.0
GOFLAGS     := -ldflags "-X main.version=$(VERSION)"
VENV        := .venv
GOBIN       := $(shell go env GOPATH)/bin
INSTALL_DIR := $(HOME)/.local/bin
PLUGIN_DIR  := extensions/defenseclaw
DC_EXT_DIR  := $(HOME)/.defenseclaw/extensions/defenseclaw

.PHONY: build install dev-install pycli gateway gateway-cross gateway-run gateway-install \
        plugin plugin-install test cli-test cli-test-cov gateway-test go-test-cov \
        test-verbose test-file lint py-lint go-lint ts-test rego-test clean

# ---------------------------------------------------------------------------
# Aggregate targets
# ---------------------------------------------------------------------------

build: pycli gateway plugin
	@echo ""
	@echo "All components built:"
	@echo "  • Python CLI   → $(VENV)/bin/defenseclaw"
	@echo "  • Go gateway   → ./$(GATEWAY)"
	@echo "  • OpenClaw plugin → $(PLUGIN_DIR)/dist/"
	@echo ""
	@echo "Run 'make install' to install all components."

install: pycli gateway-install plugin-install
	@echo ""
	@echo "All components installed:"
	@echo "  • Python CLI   → $(VENV)/bin/defenseclaw  (activate with: source $(VENV)/bin/activate)"
	@echo "  • Go gateway   → $(INSTALL_DIR)/$(GATEWAY)"
	@echo "  • OpenClaw plugin → ~/.defenseclaw/extensions/defenseclaw/"
	@echo ""
	@echo "Next steps:"
	@echo "  source $(VENV)/bin/activate"
	@echo "  defenseclaw init"
	@echo "  defenseclaw setup guardrail   # configure LLM guardrail"

# ---------------------------------------------------------------------------
# Individual build targets
# ---------------------------------------------------------------------------

dev-install:
	@./scripts/install-dev.sh

pycli:
	@command -v uv >/dev/null 2>&1 || { echo "uv not found — install from https://docs.astral.sh/uv/"; exit 1; }
	@find cli/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	uv venv $(VENV) --python 3.12
	uv pip install -e . --python $(VENV)/bin/python
	@echo ""
	@echo "Done. Activate the environment and run:"
	@echo "  source $(VENV)/bin/activate"
	@echo "  defenseclaw --help"

gateway:
	go build $(GOFLAGS) -o $(GATEWAY) ./cmd/defenseclaw
	@echo "Built $(GATEWAY)"
	@echo "  Run with: ./$(GATEWAY)"
	@echo "  Check status: ./$(GATEWAY) status"

gateway-cross:
	@test -n "$(GOOS)" -a -n "$(GOARCH)" || { echo "Usage: make gateway-cross GOOS=linux GOARCH=amd64"; exit 1; }
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GOFLAGS) -o $(BINARY)-$(GOOS)-$(GOARCH) ./cmd/defenseclaw
	@echo "Built $(BINARY)-$(GOOS)-$(GOARCH)"

gateway-run: gateway
	./$(GATEWAY)

plugin:
	@command -v npm >/dev/null 2>&1 || { echo "npm not found — install Node.js from https://nodejs.org/"; exit 1; }
	cd $(PLUGIN_DIR) && npm install && npm run build
	@echo ""
	@echo "Built OpenClaw plugin → $(PLUGIN_DIR)/dist/"
	@echo "  Install with: make plugin-install"

# ---------------------------------------------------------------------------
# Individual install targets
# ---------------------------------------------------------------------------

gateway-install: gateway
	@mkdir -p $(INSTALL_DIR)
	@cp $(GATEWAY) $(INSTALL_DIR)/$(GATEWAY)
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		codesign -f -s - $(INSTALL_DIR)/$(GATEWAY) 2>/dev/null || true; \
	fi
	@echo "Installed $(GATEWAY) to $(INSTALL_DIR)"
	@if ! echo "$$PATH" | grep -q "$(INSTALL_DIR)"; then \
		echo ""; \
		echo "Add $(INSTALL_DIR) to your PATH:"; \
		echo "  export PATH=\"$(INSTALL_DIR):\$$PATH\""; \
	fi

plugin-install: plugin
	@if [ ! -f $(PLUGIN_DIR)/dist/index.js ]; then \
		echo "Plugin not built — run 'make plugin' first"; \
		exit 1; \
	fi
	@rm -rf $(DC_EXT_DIR)
	@mkdir -p $(DC_EXT_DIR)
	@cp $(PLUGIN_DIR)/package.json $(DC_EXT_DIR)/
	@test -f $(PLUGIN_DIR)/openclaw.plugin.json && cp $(PLUGIN_DIR)/openclaw.plugin.json $(DC_EXT_DIR)/ || true
	@cp -r $(PLUGIN_DIR)/dist $(DC_EXT_DIR)/
	@if [ -d $(PLUGIN_DIR)/node_modules ]; then \
		mkdir -p $(DC_EXT_DIR)/node_modules; \
		for dep in js-yaml argparse; do \
			if [ -d $(PLUGIN_DIR)/node_modules/$$dep ]; then \
				cp -r $(PLUGIN_DIR)/node_modules/$$dep $(DC_EXT_DIR)/node_modules/; \
			fi; \
		done; \
	fi
	@echo "Installed OpenClaw plugin to $(DC_EXT_DIR)"
	@echo "  Run 'defenseclaw setup guardrail' to register with OpenClaw"

# ---------------------------------------------------------------------------
# Test targets
# ---------------------------------------------------------------------------

test: cli-test gateway-test

cli-test:
	$(VENV)/bin/python -m unittest discover -s cli/tests -v

cli-test-cov:
	$(VENV)/bin/python -m pytest cli/tests/ -v --tb=short --cov=defenseclaw --cov-report=xml:coverage-py.xml

gateway-test:
	go test -race ./internal/gateway/ ./test/... -v

go-test-cov:
	go test -race -count=1 -coverprofile=coverage.out ./...

ts-test:
	cd $(PLUGIN_DIR) && npx vitest run

rego-test:
	PATH="$(GOBIN):$(PATH)" opa test policies/rego/ -v

test-verbose:
	$(VENV)/bin/python -m unittest discover -s cli/tests -v --failfast

test-file:
	@test -n "$(FILE)" || { echo "Usage: make test-file FILE=test_config"; exit 1; }
	$(VENV)/bin/python -m unittest cli.tests.$(FILE) -v

# ---------------------------------------------------------------------------
# Lint targets
# ---------------------------------------------------------------------------

lint: py-lint go-lint
	$(VENV)/bin/python -m py_compile cli/defenseclaw/main.py

py-lint:
	$(VENV)/bin/ruff check cli/defenseclaw/

go-lint:
	PATH="$(GOBIN):$(PATH)" golangci-lint run

clean:
	rm -f $(GATEWAY) $(BINARY)-linux-* $(BINARY)-darwin-*
	rm -rf $(VENV) cli/*.egg-info
	rm -rf $(PLUGIN_DIR)/dist $(PLUGIN_DIR)/node_modules
	rm -f coverage.out coverage-py.xml
	find cli/ -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
