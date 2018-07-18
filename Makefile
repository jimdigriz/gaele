.PHONY: all
all: env/.stamp lib/.stamp
	. env/bin/activate && dev_appserver.py app.yaml --log_level debug

.PHONY: clean
clean:
	rm -rf env lib

env/.stamp:
	rm -rf env
	virtualenv env 
	touch $@

lib/.stamp: requirements.txt | env/.stamp
	. env/bin/activate && pip install -t lib -r requirements.txt
	touch $@
