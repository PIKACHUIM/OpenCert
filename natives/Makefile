# GlobalTrusts Native Client - 跨平台构建脚本

APP_NAME := native-client
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.Version=$(VERSION)

# 源码路径
CMD := ./cmd/native

# 输出目录
DIST := ./dist

# Go 参数
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOFMT := $(GOCMD) fmt
GOMOD := $(GOCMD) mod

.PHONY: all build build-windows build-linux build-darwin clean fmt test tidy

all: build

## build: 构建当前平台版本
build:
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP_NAME) $(CMD)

## build-windows: 构建 Windows 版本
build-windows:
	@echo "构建 Windows amd64..."
	@mkdir -p $(DIST)/windows-amd64
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(DIST)/windows-amd64/$(APP_NAME).exe $(CMD)

## build-linux: 构建 Linux 版本
build-linux:
	@echo "构建 Linux amd64..."
	@mkdir -p $(DIST)/linux-amd64
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(DIST)/linux-amd64/$(APP_NAME) $(CMD)

## build-darwin: 构建 macOS 版本
build-darwin:
	@echo "构建 macOS arm64..."
	@mkdir -p $(DIST)/darwin-arm64
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(DIST)/darwin-arm64/$(APP_NAME) $(CMD)

## build-all: 构建所有平台版本
build-all: build-windows build-linux build-darwin
	@echo "所有平台构建完成"

## clean: 清理构建产物
clean:
	$(GOCLEAN)
	@rm -rf $(DIST)

## fmt: 格式化代码
fmt:
	$(GOFMT) ./...

## test: 运行测试
test:
	$(GOTEST) -v -count=1 ./...

## tidy: 整理依赖
tidy:
	$(GOMOD) tidy

## lint: 运行静态检查
lint:
	golangci-lint run ./...

## run: 本地运行
run:
	$(GOCMD) run $(CMD)

## help: 显示帮助
help:
	@echo "GlobalTrusts Native Client 构建命令"
	@echo ""
	@echo "用法: make <target>"
	@echo ""
	@echo "目标:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
