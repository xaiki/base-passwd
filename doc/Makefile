DOCS := users-and-groups.html

all: $(DOCS)

clean:
	rm -f $(DOCS)

%.html: %.sgml
	sgmltools -b onehtml $<
