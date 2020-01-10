EXTRA_FILES = oddjob.xml.in
noinst_DATA = oddjob.html
if REFORMAT_XML_DOCS
XMLTO = @PATH_XMLTO@
oddjob.html: oddjob.xml
	$(XMLTO) html-nochunks $^
endif
