SHELL := /bin/bash
.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install Node dependencies (npm workspaces)
	npm install

build: ## Type-check and build all TypeScript packages
	npm run build

test: ## Run TypeScript tests (vitest)
	npm test

test-go: ## Run Go tests (inside the workers module)
	cd workers && go test ./...

test-all: test test-go ## Run all tests

conformance: ## Run the TS/Go scope-conformance check against shared fixtures
	npm run conformance

worker-build: ## Build the discovery worker binary
	go build -o bin/reconnexus-worker ./workers/cmd/reconnexus-worker

typecheck: ## Type-check without emitting
	npm run typecheck

doctor: ## Run the dependency doctor
	npm run rn -- doctor

providers: ## List provider health
	npm run rn -- providers list

migrate: ## Apply database migrations
	npm run rn -- config migrate

migrate-status: ## Show migration status
	npm run rn -- config migrate --status

go-build: ## Build Go worker binaries
	go build -o bin/worker ./workers/cmd/worker
	go build -o bin/provider-check ./workers/cmd/provider-check
	go build -o bin/reconnexus-worker ./workers/cmd/reconnexus-worker

clean: ## Remove build output and artifacts
	rm -rf dist .reconnexus bin packages/*/dist apps/*/dist

.PHONY: help install build test test-go test-all conformance worker-build typecheck doctor providers migrate migrate-status go-build clean
