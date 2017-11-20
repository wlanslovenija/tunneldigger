bin_PROGRAMS = l2tp_client
l2tp_client_SOURCES = l2tp_client.c

l2tp_client_CFLAGS = \
	@LIBASYNCNS_CFLAGS@ \
	@LIBNL_CFLAGS@ \
	@LIBNL_TINY_CFLAGS@

l2tp_client_LDADD = \
	@LIBASYNCNS_LIBS@ \
	@LIBNL_LIBS@ \
	@LIBNL_TINY_LIBS@\
	-lpthread -lresolv -lrt

if ! USE_LIBASYNCNS
# Use bundled version of libasyncns
l2tp_client_SOURCES += libasyncns/asyncns.c
endif
