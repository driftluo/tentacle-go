MOLC    := moleculec
MOLC_VERSION := 0.8.0
MOLC_GO := moleculec-go
MOLC_GO_VERSION := 0.1.11

MOL_FILES := \
  mol/protocol_select.mol \
  secio/mol/handshake.mol \
  protocols/identify/mol/protocol.mol \
  protocols/ping/mol/protocol.mol \
  protocols/discovery/mol/protocol.mol \

MOL_GO_FILES := $(patsubst %.mol,%_mol.go,${MOL_FILES})

test:
	go test -count=1 .
	go test -count=1 ./tests
	go test -count=1 ./secio

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}
	test "$$(${MOLC_GO} --version | awk '{ print $$3 }' | tr -d ' ')" = ${MOLC_GO_VERSION}

%_mol.go: %.mol check-moleculec-version
	${MOLC} --language go --schema-file $< | gofmt > $@

gen-mol: $(MOL_GO_FILES)

clean-mol:
	rm -f $(MOL_GO_FILES)

.PHONY: test check-moleculec-version gen-mol clean-mol
