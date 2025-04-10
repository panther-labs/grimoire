MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(MAKEFILE_PATH))
BIN_DIR := $(ROOT_DIR)/bin

build:
	@echo "Building Grimoire..."
	@mkdir -p "$(BIN_DIR)"
	@go build -o $(BIN_DIR)/grimoire cmd/grimoire/*.go
	@echo "Build completed. Binaries are saved in $(BIN_DIR)"

test:
	@echo "Running unit tests..."
	@go test ./... -v

thirdparty-licenses:
	@echo "Retrieving third-party licenses..."
	@go install github.com/google/go-licenses@latest
	@$(GOPATH)/bin/go-licenses csv github.com/datadog/grimoire/cmd/grimoire | sort > $(ROOT_DIR)/LICENSE-3rdparty.csv
	@echo "Third-party licenses retrieved and saved to $(ROOT_DIR)/LICENSE-3rdparty.csv"

mocks:
	@echo "Generating mocks..."
	@mockery --dir $(GOPATH)/src/github.com/DataDog/stratus-red-team/v2/pkg/stratus/runner --name Runner --output=pkg/grimoire/detonators/mocks --structname StratusRedTeamRunner --filename StratusRedTeamRunner.go
	@echo "Mocks generated successfully."

update-stratus:
	@echo "Updating stratus-red-team to latest commit..."
	@echo "Fetching latest commit hash..."
	@if ! latest_commit=$$(git ls-remote https://github.com/panther-labs/stratus-red-team.git refs/heads/main | cut -f1); then \
		echo "Error: Failed to fetch latest commit hash"; \
		exit 1; \
	fi; \
	echo "Fetching commit details..."; \
	if ! commit_info=$$(curl -s -S -f https://api.github.com/repos/panther-labs/stratus-red-team/commits/$${latest_commit}); then \
		echo "Error: Failed to fetch commit details from GitHub API"; \
		exit 1; \
	fi; \
	echo "Processing commit information..."; \
	commit_date=$$(echo "$$commit_info" | grep -o '"date": "[^"]*"' | head -1 | sed 's/"date": "\(.*\)"/\1/' | sed 's/[-:]//g' | sed 's/T//g' | cut -c 1-14); \
	commit_id=$${latest_commit:0:12}; \
	version_string="v2.0.0-$$commit_date-$$commit_id"; \
	echo "Updating go.mod file directly..."; \
	if grep -q "replace github.com/datadog/stratus-red-team/v2" go.mod; then \
		sed -i.bak "s|replace github.com/datadog/stratus-red-team/v2.*|replace github.com/datadog/stratus-red-team/v2 => github.com/panther-labs/stratus-red-team/v2 $$version_string|" go.mod && rm -f go.mod.bak; \
	else \
		echo "" >> go.mod; \
		if ! grep -q "//Run \`make update-stratus\` to update this automatically" go.mod; then \
			echo "//Run \`make update-stratus\` to update this automatically" >> go.mod; \
		fi; \
		echo "replace github.com/datadog/stratus-red-team/v2 => github.com/panther-labs/stratus-red-team/v2 $$version_string" >> go.mod; \
	fi; \
	echo "Updated stratus-red-team to $$version_string"; \
	go mod tidy