PUB =	masqitt_publisher
SUB =	masqitt_subscriber

all:	$(PUB) $(SUB)

MASQITT = ..

IDIRS = -I$(MASQITT)/include
LDIRS = -L$(MASQITT)

MIRACL = ../libmiracl.a

LIBS = -lmasqitt -lmosquitto -lwolfssl $(MIRACL)

$(PUB): $(PUB).c
	gcc $< -Debug -o $@ $(IDIRS) $(LDIRS) $(LIBS)

$(SUB): $(SUB).c
	gcc $< -Debug -o $@ $(IDIRS) $(LDIRS) $(LIBS)

test:

install:

uninstall:

TARFILES = \
	README.md \
	Makefile \
	$(PUB).c \
	$(SUB).c

.tarfiles:	$(TARFILES)
	@for f in $(TARFILES); do \
		echo $${f}; \
	done | sort -f | uniq > .tarfiles; \

tar:	.tarfiles

clean:
	rm -f $(PUB) $(SUB)

realclean:	clean
	rm -f *.o *~ .tarfiles
