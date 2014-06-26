EXTRA_DIST = users-and-groups.sgml
doc_DATA = users-and-groups.html users-and-groups.txt
CLEANFILES = $(doc_DATA)

# Here we work around sgmltools stupidity...
users-and-groups.html: users-and-groups.sgml
	cp $(srcdir)/users-and-groups.sgml $(top_builddir)
	sgmltools -b onehtml $(top_builddir)/users-and-groups.sgml
	mv $(top_builddir)/users-and-groups.html $(builddir)
	rm -f $(top_builddir)/users-and-groups.sgml

users-and-groups.txt: users-and-groups.sgml users-and-groups.html
	cp $(srcdir)/users-and-groups.sgml $(top_builddir)
	sgmltools -b txt $(top_builddir)/users-and-groups.sgml
	mv $(top_builddir)/users-and-groups.txt $(builddir)
	rm -f $(top_builddir)/users-and-groups.sgml
