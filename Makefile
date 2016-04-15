MMARK=../../mmark
XML2RFC=xml2rfc
SOURCES=mta-sts.md reporting.md
XML=$(SOURCES:.md=.xml)
TXT=$(SOURCES:.md=.txt)

all: $(XML) $(TXT)

$(XML): $(SOURCES)
	$(MMARK) -xml2 -page $< > $@ 
	
$(TXT): $(XML)
	$(XML2RFC) --text $< $@
