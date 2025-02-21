GIT := git
FIND := find
CHMOD := chmod
XARGS := xargs
GOLANG := /tgdesenv/bin/go

ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

export GOPATH := $(ROOT_DIR)/.go

all: golang-auth-hostbased

.PHONY: hostbased.go vendor clean all

$(ROOT_DIR)/vendor/modules.txt:
	$(GOLANG) mod vendor

$(ROOT_DIR)/vendor/golang.org/x/crypto/ssh/hostbased.go:
	$(GIT) checkout -f $@

golang-auth-hostbased: main.go $(ROOT_DIR)/vendor/modules.txt $(ROOT_DIR)/vendor/golang.org/x/crypto/ssh/hostbased.go
	$(GOLANG) build -ldflags="-w -s" -trimpath -o $(ROOT_DIR)/$@

clean: remove $(ROOT_DIR)/vendor/golang.org/x/crypto/ssh/hostbased.go

remove:
	$(FIND) $(ROOT_DIR)/.go | $(XARGS) -r $(CHMOD) 777
	$(RM) -rf $(ROOT_DIR)/.go $(ROOT_DIR)/vendor $(ROOT_DIR)/golang-auth-hostbased
