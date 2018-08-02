DOMAINS = example.com

.PHONY: all
all: .storage/.stamp | env/.stamp lib/.stamp
	. env/bin/activate && dev_appserver.py app.yaml --log_level debug --storage_path=.storage 

.PHONY: clean
clean:
	rm -rf env lib .storage .deploy $(wildcard *.pyc)

.PHONY: deploy
deploy: VERSION_ID = $(shell git rev-parse --short HEAD)$(shell git diff-files --quiet || echo -dirty)
deploy:
ifeq ($(PROJECT_ID),)
	@echo please provide PROJECT_ID >&2; exit 1
endif
ifeq ($(IKNOWWHATIAMDOING),)
	@git diff-files --quiet || { echo no dirty deploys >&2; git status; exit 1; }
endif
	rm -rf .$@
	mkdir .$@
	cp app.yaml cron.yaml appengine_config.py main.py .$@
	pip install -t .$@/lib -r requirements.txt
	cd .$@ && gcloud --project=$(PROJECT_ID) app deploy app.yaml \
				--version $(VERSION_ID) \
				--promote \
				--stop-previous-version
	rm -rf .$@

env/.stamp:
	@rm -rf env
	virtualenv env
	@touch $@

lib/.stamp: requirements.txt requirements-dev.txt | env/.stamp
	. env/bin/activate && pip install -t lib -r requirements.txt -r requirements-dev.txt
	@touch $@

.storage/.stamp:
	mkdir -p $(@D)
	@touch $@
