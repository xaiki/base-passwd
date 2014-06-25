EXTRA_DIST = users-and-groups.sgml
doc_DATA = users-and-groups.html users-and-groups.txt
CLEANFILES = $(doc_DATA)

users-and-groups.html: users-and-groups.sgml
	cp $(srcdir)/users-and-groups.sgml $(builddir)
	sgmltools -b onehtml $(builddir)/users-and-groups.sgml
	rm -f $(builddir)/users-and-groups.sgml

users-and-groups.txt: users-and-groups.sgml
	cp $(srcdir)/users-and-groups.sgml $(builddir)
	sgmltools -b txt $(builddir)/users-and-groups.sgml
	rm -f $(builddir)/users-and-groups.sgml
