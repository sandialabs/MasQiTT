GENCA = generate_ca
GENCL = generate_client_cert

all:	$(GENCA) $(GENCL)

test:

install: all
	install -d -o kms /home/kms/bin
	install -m 0500 -o kms $(GENCA) /home/kms/bin/$(GENCA)
	install -m 0500 -o kms $(GENCL) /home/kms/bin/$(GENCL)
	install -d -m 0700 -o kms /home/kms/ca

uninstall:

TARFILES = \
	$(GENCA) \
	$(GENCL) \
	README.md \
	Makefile

.tarfiles:	$(TARFILES)
	@for f in $(TARFILES); do \
		echo $${f}; \
	done | sort -f | uniq > .tarfiles; \

tar:	.tarfiles

clean:
	rm -f *.o

realclean:	clean
	rm -f *~ .tarfiles
