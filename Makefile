all:
	mmark -xml2 -page spec.md > spec.xml && \
        xml2rfc --text spec.xml 
