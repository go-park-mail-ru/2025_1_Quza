include auth.env
export

LOCAL_BIN:=$(CURDIR)/bin
GOOSE_CMD=${LOCAL_BIN}/goose


install-minimock:
	GOBIN=${LOCAL_BIN} go install github.com/gojuno/minimock/v3/cmd/minimock@v3.4.1

install-golangci-lint:
	$(LOCAL_BIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

lint:
	$(LOCAL_BIN)/golangci-lint cache clean
	$(LOCAL_BIN)/golangci-lint run ./... --config .golangci.pipeline.yaml



install-deps:
	@[ -f $(LOCAL_BIN)/minimock ] 			 	 || GOBIN=$(LOCAL_BIN) go install github.com/gojuno/minimock/v3/cmd/minimock@latest
	@[ -f $(LOCAL_BIN)/protoc-gen-go ] 			 || GOBIN=$(LOCAL_BIN) go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.1
	@[ -f $(LOCAL_BIN)/protoc-gen-go-grpc ]      || GOBIN=$(LOCAL_BIN) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
	@[ -f $(LOCAL_BIN)/goose ]                   || GOBIN=$(LOCAL_BIN) go install github.com/pressly/goose/v3/cmd/goose@v3.14.0
	@[ -f $(LOCAL_BIN)/protoc-gen-validate ]     || GOBIN=$(LOCAL_BIN) go install github.com/envoyproxy/protoc-gen-validate@v1.0.4
	@[ -f $(LOCAL_BIN)/protoc-gen-grpc-gateway ] || GOBIN=$(LOCAL_BIN) go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.20.0
	@[ -f $(LOCAL_BIN)/protoc-gen-openapiv2 ] || GOBIN=$(LOCAL_BIN) go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v2.15.2
	@[ -f $(LOCAL_BIN)/statik ] || GOBIN=$(LOCAL_BIN) go install github.com/rakyll/statik@v0.1.7

get-deps:
	go get -u google.golang.org/protobuf/cmd/protoc-gen-go
	go get -u google.golang.org/grpc/cmd/protoc-gen-go-grpc


generate:
	mkdir -p pkg/swagger
	make generate-user
	make generate-auth
	make generate-access
	$(LOCAL_BIN)/statik -src=pkg/swagger/ -include='*.css,*.html,*.js,*.json,*.png'


generate-user:
	mkdir -p pkg/user_v1
	protoc --proto_path=./api/proto/user_v1 --proto_path vendor.protogen \
	--go_out=pkg/user_v1 --go_opt=paths=source_relative \
	--plugin=protoc-gen-go=bin/protoc-gen-go \
	--go-grpc_out=pkg/user_v1 --go-grpc_opt=paths=source_relative \
	--plugin=protoc-gen-go-grpc=bin/protoc-gen-go-grpc \
	--grpc-gateway_out=pkg/user_v1 --grpc-gateway_opt=paths=source_relative \
	--plugin=protoc-gen-grpc-gateway=bin/protoc-gen-grpc-gateway \
	--validate_out lang=go:pkg/user_v1 --validate_opt=paths=source_relative \
	--plugin=protoc-gen-validate=bin/protoc-gen-validate \
	--openapiv2_out=allow_merge=true,merge_file_name=api:pkg/swagger \
    --plugin=protoc-gen-openapiv2=bin/protoc-gen-openapiv2 \
	./api/proto/user_v1/user.proto ./api/proto/user_v1/models.proto

generate-auth:
	mkdir -p pkg/auth_v1
	protoc --proto_path=./api/proto/auth_v1 --proto_path vendor.protogen \
	--go_out=pkg/auth_v1 --go_opt=paths=source_relative \
	--plugin=protoc-gen-go=bin/protoc-gen-go \
    --go-grpc_out=pkg/auth_v1 --go-grpc_opt=paths=source_relative \
	--validate_out lang=go:pkg/auth_v1 --validate_opt=paths=source_relative \
    --plugin=protoc-gen-validate=bin/protoc-gen-validate \
	./api/proto/auth_v1/auth.proto



build:
	GOOS=linux GOARCH=amd64 go build -o auth_linux cmd/main.go


local-migration-status:
	${GOOSE_CMD} -dir ${MIGRATION_DIR} postgres ${PG_DSN} status -v

local-migration-up:
	${GOOSE_CMD} -dir ${MIGRATION_DIR} postgres ${PG_DSN} up -v

local-migration-down:
	${GOOSE_CMD} -dir ${MIGRATION_DIR} postgres ${PG_DSN} down -v

local-migration-create:
	@if [ -z "$(name)" ]; then \
		echo "Please provide a migration name, usage: make local-migration-create name=add_table"; \
		exit 1; \
	fi
	${GOOSE_CMD} -dir ${MIGRATION_DIR} create $(name) sql


docker-up:
	docker compose -f ./deploy/docker-compose.yaml up -d

docker-down:
	docker compose -f ./deploy/docker-compose.yaml down


test:
	go clean -testcache
	go test ./... -covermode count -coverpkg=github.com/Dnlbb/auth/internal/service/authserv/...,github.com/Dnlbb/auth/internal/api/auth/... -count 5


test-coverage:
	go clean -testcache
	go test ./... -coverprofile=coverage.tmp.out -covermode count -coverpkg=github.com/Dnlbb/auth/internal/service/userserv/...,github.com/Dnlbb/auth/internal/api/user/... -count 5
	rm -rf coverage
	mkdir -p coverage
	grep -v 'mocks\|config' coverage.tmp.out > coverage/coverage.out
	rm coverage.tmp.out
	go tool cover -html=coverage/coverage.out -o coverage/coverage.html;
	go tool cover -func=./coverage/coverage.out | grep "total";
	grep -sqFx "/coverage/coverage.out" .gitignore || echo "/coverage/coverage.out" >> .gitignore
	grep -sqFx "/coverage/coverage.html" .gitignore || echo "/coverage/coverage.html" >> .gitignore


vendor-proto:
		@if [ ! -d vendor.protogen/validate ]; then \
			mkdir -p vendor.protogen/validate &&\
			git clone https://github.com/envoyproxy/protoc-gen-validate vendor.protogen/protoc-gen-validate &&\
			mv vendor.protogen/protoc-gen-validate/validate/*.proto vendor.protogen/validate &&\
			rm -rf vendor.protogen/protoc-gen-validate ;\
		fi
		@if [ ! -d vendor.protogen/google ]; then \
			git clone https://github.com/googleapis/googleapis vendor.protogen/googleapis &&\
			mkdir -p  vendor.protogen/google/ &&\
			mv vendor.protogen/googleapis/google/api vendor.protogen/google &&\
			rm -rf vendor.protogen/googleapis ;\
		fi
		@if [ ! -d vendor.protogen/protoc-gen-openapiv2 ]; then \
        	mkdir -p vendor.protogen/protoc-gen-openapiv2/options &&\
        	git clone https://github.com/grpc-ecosystem/grpc-gateway vendor.protogen/openapiv2 &&\
        	mv vendor.protogen/openapiv2/protoc-gen-openapiv2/options/*.proto vendor.protogen/protoc-gen-openapiv2/options &&\
        	rm -rf vendor.protogen/openapiv2 ;\
        fi