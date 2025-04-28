all:

INSTFILES = \
	masqitt.h \
	masqlib.h \
	api.h \
	crypto.h \
	ibe.h \
	keys.h \
	kms_msg.h \
	kms_utils.h \
	tls.h

install:
	install -d "${DESTDIR}/usr/include/masqitt"
	set -e; for f in $(INSTFILES); do install -m 444 $${f} "${DESTDIR}/usr/include/masqitt/$${f}"; done

uninstall:
	rm -rf "${DESTDIR}/usr/include/masqitt"

TARFILES = \
	Makefile \
	$(INSTFILES)

.tarfiles:	$(TARFILES)
	@for f in $(TARFILES); do \
		echo $${f}; \
	done | sort -f | uniq > .tarfiles; \

tar:	.tarfiles

clean:

realclean:	clean
	rm -f *~ .tarfiles
