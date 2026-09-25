.PHONY: help install uninstall fmt validate tftest test image bundle provider clean

# the terraform.rc that `make provider` writes: it honours CLOUDSEED_HOME exactly like cloudseed does
TF_RC := $(shell python3 -c 'from cloudseed import localvm; print(localvm.TERRAFORM_RC)' 2>/dev/null)
ifeq ($(strip $(TF_RC)),)
TF_RC := $(or $(CLOUDSEED_HOME),$(HOME)/.cloudseed)/terraform.rc
endif
# terraform init's provider caches go to build/tfdata/<root>, never into terraform/*/ (images and bundles copy that tree)
TF_DATA := $(CURDIR)/build/tfdata
# every stack with a mocked `terraform test` suite (terraform/<cloud>/tests/*.tftest.hcl): aws, azure and gcp today
TF_SUITES := $(sort $(patsubst terraform/%/tests/,%,$(dir $(wildcard terraform/*/tests/*.tftest.hcl))))

help:
	@echo "make install    symlink bin/cloudseed (and the cs alias) onto your PATH (scripts/install.sh --help)"
	@echo "make uninstall  remove those links again"
	@echo "make fmt        terraform fmt"
	@echo "make validate   terraform validate every root (cloud stacks, bootstraps, vmware via the local provider)"
	@echo "make tftest     terraform test: every mocked suite in terraform/<cloud>/tests ($(TF_SUITES); no cloud access)"
	@echo "make provider   build the VMware Terraform provider into \$$CLOUDSEED_HOME/providers (default ~/.cloudseed)"
	@echo "make test       python unit tests (rendering, CIDR picking, CLI parsing)"
	@echo "make image      build the all-in-one container image"
	@echo "make bundle     build a single self-contained binary"
	@echo "make clean      remove build output (incl. build/tfdata) and provider caches older runs left in terraform/*/ (tracked lock files stay)"

install:
	./scripts/install.sh

uninstall:
	./scripts/install.sh --uninstall

fmt:
	terraform fmt -recursive terraform

validate: provider
	@for d in aws aws-bootstrap gcp gcp-bootstrap azure azure-bootstrap vmware; do \
	  echo "== $$d"; (cd terraform/$$d && export TF_DATA_DIR="$(TF_DATA)/$$d" && \
	    TF_CLI_CONFIG_FILE="$(TF_RC)" terraform init -backend=false -input=false >/dev/null && terraform validate) || exit 1; \
	done
	@cd providers/vmdesktop && go vet ./... && echo "== provider: go vet ok"

tftest:
	@test -n "$(TF_SUITES)" || { echo "no terraform/*/tests/*.tftest.hcl suites found"; exit 1; }
	@for d in $(TF_SUITES); do \
	  echo "== $$d"; (cd terraform/$$d && export TF_DATA_DIR="$(TF_DATA)/$$d" && \
	    terraform init -backend=false -input=false >/dev/null && terraform test) || exit 1; \
	done

provider:
	./bin/cloudseed install vmware-provider

test:
	python3 -m unittest discover -s tests -v

image:
	./bin/cloudseed deps image

bundle:
	./scripts/build-bundle.sh

# the registry roots' .terraform.lock.hcl are tracked (they pin the providers `make validate` uses): never removed here;
# terraform/vmware's pins a provider built on this machine and is not tracked (.gitignore)
clean:
	rm -rf build dist terraform/*/.terraform
