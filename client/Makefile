all: l2tp_client

l2tp_client: l2tp_client.o asyncns.o
	$(CC) $(LDFLAGS) -o $@ $^ -lpthread -lnl -lrt -lresolv

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -I. -o $@ $<

clean:
	rm -rf *.o l2tp_client

