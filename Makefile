TARFILES = \
	README.md \
	MasQiTT.png \
	Makefile

# shared library version, increment if incompatible changes are made
SOVERS = 1

MASQ = masqitt
MASQDB = masqittdb

MASQITT = lib$(MASQ).so
MASQITTDB = lib$(MASQDB).so

DIRS = lib tests examples
# only install from lib, "make -C {ca,kms} install" manually as needed
INSTDIRS = lib

all:
	@set -e; for d in $(DIRS); do $(MAKE) -C $${d} all; done
	@set -e; if `grep -q -e '^kms:' /etc/passwd`; then $(MAKE) -C kms $@; fi
	@set -e; if `grep -q -e '^kms:' /etc/passwd`; then $(MAKE) -C ca $@; fi

help:
	@echo Valid make targets are: all, test, clean, realclean, tar, install, uninstall, help | fmt -w 76
	@echo Note: KMS targets are not made unless there is a kms userid in /etc/passwd

test:	all
	@set -e; for d in $(INSTDIRS) tests kms; do $(MAKE) -C $${d} $@; done

LIBDIR = /usr/local/lib

install:
	@set -e; for d in $(DIRS); do $(MAKE) -C $${d} $@; done
	@set -e; if `grep -q -e '^kms:' /etc/passwd`; then $(MAKE) -C kms $@; fi
	@set -e; if `grep -q -e '^kms:' /etc/passwd`; then $(MAKE) -C ca $@; fi

uninstall:
	@set -e; for d in $(DIRS); do $(MAKE) -C $${d} $@; done
	@set -e; if `grep -q -e '^kms:' /etc/passwd`; then $(MAKE) -C kms $@; fi
	@set -e; if `grep -q -e '^kms:' /etc/passwd`; then $(MAKE) -C ca $@; fi

# ordering of dependency targets is important here

tar:	.tarfiles subtars
	tar czf masqitt.tgz $$(sort .tarfiles | uniq)

.tarfiles:	$(TARFILES)
	@echo "> .tarfiles"
	@rm -f .tarfiles
	@for t in $(TARFILES); do echo $${t}; done >> .tarfiles

subtars:
	@echo "> subtars"
	@set -e; for d in $(DIRS) kms ca include; do \
		$(MAKE) -C $${d} tar; \
		for f in $$(cat $${d}/.tarfiles); do \
			echo $${d}/$${f}; \
		done >> .tarfiles; \
	done
	@sort -f .tarfiles | uniq > .tarfiles2 && mv .tarfiles2 .tarfiles

myclean:
	rm -f *~

clean:	myclean
	@set -e; for d in $(DIRS) kms ca include; do $(MAKE) -C $${d} $@; done

myrealclean:	myclean
	rm -f *.tgz .tarfiles
	rm -f $(MASQITT) $(MASQITT).$(SOVERS)
	rm -f $(MASQITTDB) $(MASQITTDB).$(SOVERS)

realclean:	myrealclean
	@set -e; for d in $(DIRS) kms ca include; do $(MAKE) -C $${d} $@; done
