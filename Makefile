.PHONY: all
all: env/.stamp lib/.stamp
	. env/bin/activate && dev_appserver.py app.yaml --log_level debug

.PHONY: clean
clean:
	rm -rf env lib

.PHONY: deploy
deploy: VERSION_ID = $(shell git rev-parse --short HEAD)
deploy:
ifeq ($(PROJECT_ID),)
	@echo please provide PROJECT_ID >&2; exit 1
endif
	git diff-files --quiet || { echo no dirty deploys >&2; git status; exit 1; }
	gcloud --project=$(PROJECT_ID) app deploy --version $(VERSION_ID)

env/.stamp:
	rm -rf env
	virtualenv env 
	touch $@

lib/.stamp: requirements.txt | env/.stamp
	. env/bin/activate && pip install -t lib -r requirements.txt
	touch $@
