MIRDIR = ../../core/c
MIRACL = ../libmiracl.a

LIBS = -lmosquitto -lwolfssl -lconfig $(MIRACL)

CFLAGS = 

KMS = kms
PRINT = print_cache
MPARAMS = make_params
CTRL = kms_ctrl
RAND = rand_id
CFG = kms.cfg
TCFG = kms-test.cfg

all:	$(KMS) $(PRINT) $(MPARAMS) $(CTRL) $(RAND) $(CFG) $(TCFG)

MASQ = masqitt
MASQDB = $(MASQ)db
MASQITT = ../lib$(MASQ).so
MASQITTDB = ../lib$(MASQDB).so

$(MASQITT):
	@echo MasQiTT library not found, cd .. and make && exit 1

$(MASQITTDB):
	@echo MasQiTT debug library not found, cd .. and make test && exit 1

$(MIRACL):
	@echo MIRACL Core library not found, cd .. and make && exit 1

test:	$(KMS)db $(MPARAMS)db

KSRCS = kms_main.c \
	cache.c \
	cfg.c \
	strings.c

KOBJS = $(KSRCS:.c=.o)
KTOBJS = $(KSRCS:.c=.db.o)

HDRS = cache.h \
	cfg.h \
	strings.h

PSRCS = print_cache.c \
	cache.c

POBJS = $(PSRCS:.c=.o)

PHDRS = cache.h

MSRCS = make_params.c \
	cache.c \
	strings.c

MTOBJS = $(MSRCS:.c=.db.o)
MOBJS = $(MSRCS:.c=.o)

MHDRS = cache.h

CSRCS = kms_ctrl.c \
	cache.c

COBJS = $(CSRCS:.c=.o)

CHDRS = cache.h

RSRCS = rand_id.c

RHDRS =

ROBJS = $(RSRCS:.c=.o)

SRCS = $(KSRCS) $(PSRCS) $(MSRCS) $(CSRCS) $(RSRCS)

IDIRS = -I../include -I$(MIRDIR)

%.o:	%.c
	gcc -o $@ -g -Wunused $(CFLAGS) $(IDIRS) -c $<

%.db.o:	%.c
	gcc -o $@ -Debug -g -Wunused $(CFLAGS) $(IDIRS) -c $<

DIR = ..

$(KMS):	$(KOBJS) $(MASQITT) $(HDRS) $(MIRACL)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $(IDIRS) $(KOBJS) -L$(DIR) -l$(MASQ) $(LIBS)

$(KMS)db:	$(KTOBJS) $(MASQITTDB) $(HDRS) $(MIRACL)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $(IDIRS) $(KTOBJS) -L$(DIR) -l$(MASQDB) $(LIBS)

$(PRINT):	$(POBJS) $(PHDRS)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $(POBJS)

$(MPARAMS):	$(MOBJS) $(MHDRS) $(MIRACL)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $(MOBJS) -L$(DIR) -l$(MASQ) $(LIBS)

$(MPARAMS)db:	$(MTOBJS) $(MHDRS) $(MIRACL)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $(MTOBJS) -L$(DIR) -l$(MASQDB) $(LIBS)

$(CTRL):	$(COBJS) $(CHDRS)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $(COBJS)

$(RAND):	$(ROBJS) $(RHDRS) $(MIRACL)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $(ROBJS) -L$(DIR) -l$(MASQ) $(LIBS)

install:	all
	install -d -o kms /home/kms/bin
	install -m 0500 -o kms $(KMS) /home/kms/bin/$(KMS)
	install -m 0500 -o kms $(KMS)db /home/kms/bin/$(KMS)db
	install -m 0500 -o kms $(MPARAMS) /home/kms/bin/$(MPARAMS)
	@# do not overwrite kms.cfg
	@set -e; if [ ! -f /home/kms/$(CFG) ] ; then install -m 0600 -o kms -p $(CFG) /home/kms/$(CFG); fi
	install -m 0600 -o kms -p $(TCFG) /home/kms/$(TCFG)
	install -m 4555 -o kms $(CTRL) "${DESTDIR}/usr/local/bin/$(CTRL)"
	install -m 0555 -o kms $(RAND) /home/kms/bin/$(RAND)
	install -m 0500 -o kms $(PRINT) /home/kms/bin/$(PRINT)

uninstall:
	rm -f /home/kms/bin/$(KMS)
	rm -f /home/kms/bin/$(MPARAMS)
	rm -f /home/kms/$(CFG)
	rm -f /home/kms/*.smqtt
	rm -f "${DESTDIR}/usr/local/bin/$(CTRL)"
	rm -f /home/kms/bin/$(RAND)
	rm -f /home/kms/bin/$(PRINT)

DOXY = \
	Doxyfile

TARFILES = \
	README.md \
	Makefile \
	$(CFG) \
	$(TCFG) \
	$(KSRCS) \
	$(PSRCS) \
	$(MSRCS) \
	$(CSRCS) \
	$(RSRCS) \
	$(HDRS) \
	$(DOXY)

.tarfiles:	$(TARFILES)
	@for f in $(TARFILES); do \
		echo $${f}; \
	done | sort -f | uniq > .tarfiles; \

tar:	.tarfiles

depend:
	makedepend -- $(CFLAGS) $(IDIRS) -- $(SRCS)

doc:
	doxygen

clean:
	rm -f *.o *~

realclean:	clean
	rm -f $(KMS) $(KMS)db $(PRINT) $(MPARAMS) $(MPARAMS)db $(CTRL) $(RAND) params.smqtt .tarfiles
	rm -rf doc

# DO NOT DELETE

kms_main.o: ../include/kms_msg.h
kms_main.o: ../include/kms_utils.h ../include/crypto.h ../include/ibe.h
kms_main.o: ../include/masqlib.h ../include/tls.h ../include/keys.h
kms_main.o: cache.h cfg.h strings.h
cache.o: ../include/crypto.h ../include/ibe.h
cache.o: ../include/kms_msg.h ../include/tls.h ../include/keys.h cache.h
cfg.o: cfg.h ../include/masqlib.h
print_cache.o: cache.h ../include/masqlib.h
print_cache.o: ../include/kms_msg.h
cache.o: ../include/crypto.h ../include/ibe.h
cache.o: ../include/masqlib.h
cache.o: ../include/kms_msg.h ../include/tls.h ../include/keys.h cache.h
make_params.o: cache.h ../include/masqlib.h
make_params.o: ../include/kms_msg.h /usr/include/stdint.h ../include/crypto.h
make_params.o: ../include/ibe.h
make_params.o: ../include/tls.h
make_params.o: ../include/keys.h strings.h
cache.o: ../include/crypto.h ../include/ibe.h
cache.o: ../include/masqlib.h
cache.o: ../include/kms_msg.h ../include/tls.h ../include/keys.h cache.h
kms_ctrl.o: cache.h
kms_ctrl.o: ../include/masqlib.h ../include/kms_msg.h
cache.o: ../include/crypto.h ../include/ibe.h
cache.o: ../include/masqlib.h
cache.o: ../include/kms_msg.h ../include/tls.h ../include/keys.h cache.h
rand_id.o: ../include/masqlib.h ../include/kms_msg.h ../include/tls.h
rand_id.o: ../include/keys.h
