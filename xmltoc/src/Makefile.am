## xmltoc main Makefile.am

bin_PROGRAMS = xmltoc
xmltoc_SOURCES = xmltoc.c xmltoc.h tokenizer_tree.c tokenizer_tree.h \
                 tr_common.c tr_common.h
xmltoc_LDADD = -lxml2

if CWMPDMTOC
bin_PROGRAMS += cwmpdmtoc
cwmpdmtoc_SOURCES = cwmpdmtoc.c cwmpdmtoc.h tokenizer_tree.c tokenizer_tree.h \
                    tr_common.c tr_common.h
cwmpdmtoc_LDADD = -lexpat
endif
