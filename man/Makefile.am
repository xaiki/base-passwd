LANGS = de es fr ja ru
RAW_LANGS = pl

CLEANFILES = po4a-stamp

all-local: po4a-stamp

install-data-local: po4a/po/base-passwd.pot
	$(MKDIR_P) $(DESTDIR)$(mandir)/man8
	$(INSTALL_DATA) $(srcdir)/update-passwd.8 $(DESTDIR)$(mandir)/man8/
	set -e; for lang in $(LANGS); do \
		mkdir -p $(DESTDIR)$(mandir)/$$lang/man8; \
		$(INSTALL_DATA) $(top_builddir)/update-passwd.$$lang.8 \
			$(DESTDIR)$(mandir)/$$lang/man8/update-passwd.8; \
	done
# RAW_LANGS files live in $(srcdir)
	set -e; for lang in $(RAW_LANGS); do \
		mkdir -p $(DESTDIR)$(mandir)/$$lang/man8; \
		$(INSTALL_DATA) $(srcdir)/update-passwd.$$lang.8 \
			$(DESTDIR)$(mandir)/$$lang/man8/update-passwd.8; \
	done

uninstall-local:
	rm -f $(DESTDIR)/$(mandir)/man8/update-passwd.8
	set -e; for lang in $(LANGS) $(RAW_LANGS); do \
		rm -f $(DESTDIR)/$(mandir)/$$lang/man8/update-passwd.8; \
	done

clean-local:
	set -e; for lang in $(LANGS); do \
		rm -f $(top_builddir)/update-passwd.$$lang.8; \
	done

po4a-stamp: update-passwd.8
	cp -a $(srcdir)/po4a $(srcdir)/update-passwd.8 $(top_builddir)
	cd $(top_builddir)/po4a && po4a po4a.cfg
	chmod -R +w $(top_builddir)/po4a $(top_builddir)/update-passwd.8
	rm -rf $(top_builddir)/po4a $(top_builddir)/update-passwd.8
	touch $@

EXTRA_DIST = \
	update-passwd.8 \
	update-passwd.pl.8 \
	po4a
