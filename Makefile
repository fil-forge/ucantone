.PHONY: cover, gen

cover:
	mkdir -p coverage
	go test -coverprofile=./coverage/c.out -v ./...
	go tool cover -html=./coverage/c.out

gen:
	rm ./errors/datamodel/*_gen.go || true
	cd ./errors/datamodel/gen && go run ./main.go

	rm ./examples/types/cbor_gen.go || true
	cd ./examples/types/gen && go run ./main.go

	rm ./result/datamodel/*_gen.go || true
	cd ./result/datamodel/gen && go run ./main.go

	rm ./testutil/datamodel/cbor_gen.go || true
	cd ./testutil/datamodel/gen && go run ./main.go

	rm ./ucan/container/datamodel/*_gen.go || true
	cd ./ucan/container/datamodel/gen && go run ./main.go

	rm ./ucan/envelope/datamodel/*_gen.go || true
	cd ./ucan/envelope/datamodel/gen && go run ./main.go

	rm ./ucan/delegation/datamodel/*_gen.*.go || true
	cd ./ucan/delegation/datamodel/gen && go run ./main.go

	cd ./ucan/delegation/policy/datamodel/gen && go run ./main.go

	rm ./ucan/delegation/policy/internal/fixtures/datamodel/*_gen.go || true
	cd ./ucan/delegation/policy/internal/fixtures/datamodel/gen && go run ./main.go

	rm ./ucan/delegation/policy/selector/internal/fixtures/datamodel/*_gen.go || true
	cd ./ucan/delegation/policy/selector/internal/fixtures/datamodel/gen && go run ./main.go

	rm ./ucan/delegation/policy/selector/datamodel/*_gen.go || true
	cd ./ucan/delegation/policy/selector/datamodel/gen && go run ./main.go

	rm ./ucan/invocation/datamodel/*_gen.*.go || true
	cd ./ucan/invocation/datamodel/gen && go run ./main.go

	rm ./ucan/promise/datamodel/*_gen.go || true
	cd ./ucan/promise/datamodel/gen && go run ./main.go

	rm ./ucan/receipt/datamodel/*_gen.go || true
	cd ./ucan/receipt/datamodel/gen && go run ./main.go

	rm ./validator/internal/fixtures/datamodel/dag_json_gen.go || true
	cd ./validator/internal/fixtures/datamodel/gen && go run ./main.go
