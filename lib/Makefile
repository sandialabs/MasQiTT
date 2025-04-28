CFLAGS = 

MASQ = masqitt
MASQDB = $(MASQ)db
MOSQ = mosquitto

# shared library version, increment if incompatible changes are made
SOVERS = 1

MASQITT = ../lib$(MASQ).so
MASQITTDB = ../lib$(MASQDB).so

MIRACLDIR = ../../core
MIRACL = ../libmiracl.a

# build MIRACL first to create #include file(s) needed by ibe.c
all:	$(MIRACL) $(MASQITT)

test:	$(MASQITTDB)

LSRCS = \
	masqitt.c \
	api.c \
	crypto.c \
	keys.c \
	kms_msg.c \
	kms_utils.c \
	ibe.c

LOBJS = $(LSRCS:.c=.po)
LOBJSDB = $(LSRCS:.c=.db.po)

$(MASQITT).$(SOVERS):	$(LOBJS)
	gcc -shared -o $@ $^

$(MASQITT):	$(MASQITT).$(SOVERS)
	ln -sf $$(basename $<) $@

$(MASQITTDB).$(SOVERS):	$(LOBJSDB)
	gcc -shared -o $@ $^

$(MASQITTDB):	$(MASQITTDB).$(SOVERS)
	ln -sf $$(basename $<) $@

$(MIRACL):	miracl.json
	CC=gcc CFLAGS="-Wno-stringop-overflow -g" ./compile_miracl -s $(MIRACLDIR) -d $(MIRACL) miracl.json

INCL = -I../include -I$(MIRACLDIR)/c

MOSQUITTO = /usr/local

IMDIRS = $(INCL) -I$(MOSQUITTO)/include -I$(MOSQUITTO)/lib

CFLAGS =

%.po:	%.c
	gcc -o $@ -g -fpic -Wunused $(CFLAGS) $(IMDIRS) -c $<

%.db.po:	%.c
	gcc -o $@ -Debug -g -fpic -Wunused $(CFLAGS) $(IMDIRS) -c $<

DIR = ..
MDIR = $(MOSQUITTO)

depend:
	@echo Safest to run this by hand and fix to your liking:
	@echo $$ touch foo
	@echo $$ makedepend -ffoo -- $(CFLAGS) $(IMDIRS) -- $(LSRCS) $(CTSRCS) $(ATSRCS) $(KTSRCS) $(LTSRCS) $(QTSRCS)
	@echo $$ vi foo

install:
	$(MAKE) -C ../include $@
	install -d "${DESTDIR}/usr/local/lib"
	install -m 755 $(MASQITT).$(SOVERS) "${DESTDIR}/usr/local/lib/$$(basename $(MASQITT).$(SOVERS))"
	ln -sf $$(basename $(MASQITT).$(SOVERS)) "${DESTDIR}/usr/local/lib/$$(basename $(MASQITT))"
	install -m 755 $(MASQITTDB).$(SOVERS) "${DESTDIR}/usr/local/lib/$$(basename $(MASQITTDB).$(SOVERS))"
	ln -sf $$(basename $(MASQITTDB).$(SOVERS)) "${DESTDIR}/usr/local/lib/$$(basename $(MASQITTDB))"

uninstall:
	$(MAKE) -C ../include $@
	rm -f "${DESTDIR}/usr/local/lib/$$(basename $(MASQITT).$(SOVERS))"
	rm -f "${DESTDIR}/usr/local/lib/$$(basename $(MASQITT))"

DOXY = \
	Doxyfile

TARFILES = \
	README.md \
	Makefile \
	compile_miracl \
	miracl.json \
	$(LSRCS) \
	$(DOXY)

.tarfiles:	$(TARFILES)
	@for f in $(TARFILES); do \
		echo $${f}; \
	done | sort -f | uniq > .tarfiles; \

tar:	.tarfiles

doc:
	doxygen

clean:
	rm -f *.po

realclean:	clean
	rm -f *.so $(MIRACL) .tarfiles
	rm -rf doc

# DO NOT DELETE

api.po:	../include/crypto.h ../include/tls.h
crypto.po:	../include/crypto.h ../include/tls.h ../include/kms_msg.h
crypto.po:	../include/kms_utils.h
ibe.po:
keys.po:	../include/crypto.h ../include/tls.h
kms_msg.po:	../include/kms_msg.h ../include/kms_utils.h
kms_msg.po:	../include/masqlib.h
kms_utils.po:	../include/kms_msg.h ../include/kms_utils.h
masqitt.po:	../include/api.h ../include/crypto.h ../include/tls.h
masqitt.po:	../include/masqitt.h

api.db.po:	../include/crypto.h ../include/tls.h
crypto.db.po:	../include/crypto.h ../include/tls.h ../include/kms_msg.h
crypto.db.po:	../include/kms_utils.h
ibe.db.po:
keys.db.po:	../include/crypto.h ../include/tls.h
kms_msg.db.po:	../include/kms_msg.h ../include/kms_utils.h
kms_msg.db.po:	../include/masqlib.h
kms_utils.db.po:	../include/kms_msg.h ../include/kms_utils.h
masqitt.db.po:	../include/api.h ../include/crypto.h ../include/tls.h
masqitt.db.po:	../include/masqitt.h
