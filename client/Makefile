all: l2tp_client

l2tp_client: l2tp_client.o
	$(CC) $(LDFLAGS) -o $@ $^ -lanl -lnl -lrt

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -I. -o $@ $<

clean:
	rm -rf *.o l2tp_client

