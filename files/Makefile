CFLAGS += -Wall -Werror
LDFLAGS += -lpthread -lnl-3 -lnl-genl-3 -lrt -lresolv
EXTRA_CFLAGS += -I/usr/include/libnl3/ -DLIBNL_TINY

all: l2tp_client

l2tp_client: l2tp_client.o asyncns.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -I. -o $@ $<

clean:
	rm -rf *.o l2tp_client
