MIRDIR = ../../core/c
MIRACL = ../libmiracl.a

LIBS = -lwolfssl -lconfig -lmosquitto $(MIRACL)

CFLAGS = 

MASQ = masqitt
MASQDB = $(MASQ)db
MOSQ = mosquitto

MASQITTDB = ../lib$(MASQDB).so

# do nothing, we need 'make test' in lib/ before $(MASQITTDB) is available
all:

test:	\
	msgtest \
	kmstest \
	cryptotest \
	apitest \
	clienttest \
	masqitt_test

MTSRCS = msgtest.c
KTSRCS = kmstest.c
CTSRCS = cryptotest.c
ATSRCS = apitest.c
LTSRCS = clienttest.c
QTSRCS = masqitt_test.c

TESTSRCS = \
	$(MTSRCS) \
	$(KTSRCS) \
	$(CTSRCS) \
	$(ATSRCS) \
	$(LTSRCS) \
	$(QTSRCS)

MTOBJSDB = $(MTSRCS:.c=.db.o)
KTOBJSDB = $(KTSRCS:.c=.db.o)
CTOBJSDB = $(CTSRCS:.c=.db.o)
ATOBJSDB = $(ATSRCS:.c=.db.o)
LTOBJSDB = $(LTSRCS:.c=.db.o)
QTOBJSDB = $(QTSRCS:.c=.db.o)

INCL = ../include

MOSQUITTO = /usr/local

IDIRS = -I$(INCL)
IMDIRS = -I$(INCL) -I$(MOSQUITTO)/include -I$(MOSQUITTO)/lib -I$(MIRDIR)

#CFLAGS =

%.db.o:	%.c
	gcc -o $@ -Debug -g -Wunused $(CFLAGS) $(IMDIRS) -c $<

DIR = ..
MDIR = $(MOSQUITTO)

msgtest:	$(MTOBJSDB) $(MASQITTDB)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $< -L$(DIR) -l$(MASQDB) $(LIBS)

kmstest:	$(KTOBJSDB) $(MASQITTDB)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $< -L$(DIR) -l$(MASQDB) $(LIBS)

cryptotest:	$(CTOBJSDB) $(MASQITTDB)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $< -L$(DIR) -l$(MASQDB) $(LIBS)

apitest:	$(ATOBJSDB) $(MASQITTDB)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $< -L$(DIR) -l$(MASQDB) $(LIBS)

clienttest:	$(LTOBJSDB) $(MASQITTDB)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $< -L$(DIR) -l$(MASQDB) $(LIBS)

masqitt_test:	$(QTOBJSDB) $(MASQITTDB)
	gcc -o $@ -g -Wunused $(CFLAGS) $(LDFLAGS) $< -L$(DIR) -l$(MASQDB) -L$(MDIR) -l$(MOSQ) $(LIBS)

depend:
	@echo Safest to run this by hand and fix to your liking:
	@echo $$ touch foo
	@echo $$ makedepend -ffoo -- $(CFLAGS) $(IMDIRS) -- $(LSRCS) $(CTSRCS) $(ATSRCS) $(KTSRCS) $(LTSRCS) $(QTSRCS)
	@echo $$ vi foo

install:

uninstall:

TARFILES = \
	README.md \
	Makefile \
	$(TESTSRCS) \
	certs/*.pem

.tarfiles:	$(TARFILES)
	@for f in $(TARFILES); do \
		echo $${f}; \
	done | sort -f | uniq > .tarfiles; \

tar:	.tarfiles

doc:

clean:
	rm -f *.o *.po

realclean:	clean
	rm -f *~ cryptotest apitest msgtest kmstest clienttest masqitt_test
	rm -f .tarfiles
	rm -rf doc

# DO NOT DELETE

msgtest.db.o: ../include/masqlib.h ../include/kms_msg.h ../include/kms_utils.h
kmstest.db.o: ../include/masqlib.h ../include/kms_msg.h 

apitest.db.o: ../include/masqlib.h ../include/crypto.h ../include/ibe.h 
apitest.db.o: ../include/kms_msg.h ../include/keys.h ../include/api.h

cryptotest.db.o: ../include/crypto.h ../include/ibe.h ../include/masqlib.h
cryptotest.db.o: ../include/kms_msg.h ../include/keys.h

apitest.db.o: ../include/masqlib.h ../include/crypto.h ../include/ibe.h 
apitest.db.o: ../include/kms_msg.h ../include/keys.h ../include/api.h

clienttest.db.o: ../include/masqlib.h ../include/api.h ../include/crypto.h
clienttest.db.o: ../include/ibe.h ../include/kms_msg.h ../include/keys.h

masqitt_test.db.o: ../include/masqitt.h ../include/masqlib.h ../include/crypto.h
masqitt_test.db.o: ../include/ibe.h ../include/kms_msg.h ../include/keys.h
masqitt_test.db.o: ../include/api.h
