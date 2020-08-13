MOLC    := moleculec
MOLC_VERSION := 0.6.0
MOLC_GO := moleculec-go
MOLC_GO_VERSION := 0.1.4

MOL_FILES := \
  mol/protocol_select.mol \
  secio/mol/handshake.mol \
  protocols/identify/mol/protocol.mol \
  protocols/ping/mol/protocol.mol \

MOL_GO_FILES := $(patsubst %.mol,%_mol.go,${MOL_FILES})

test:
	go test .
	go test ./tests
	go test ./secio

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}
	test "$$(${MOLC_GO} --version | awk '{ print $$4 }' | tr -d ' ')" = ${MOLC_GO_VERSION}

%_mol.go: %.mol check-moleculec-version
	${MOLC} --language go --schema-file $< | gofmt > $@

gen-mol: $(MOL_GO_FILES)

clean-mol:
	rm -f $(MOL_GO_FILES)

.PHONY: test check-moleculec-version gen-mol clean-mol
