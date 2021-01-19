CFLAGS += -Wall -O3

.PHONY: all clean

all: dt pmgr

dt: src/dt.c src/dt.h
	$(CC) $(CFLAGS) -o $@ -DDT_MAIN -DDT_IO src/dt.c

pmgr: src/pmgr.c src/dt.c src/pmgr.h src/dt.h
	$(CC) $(CFLAGS) -o $@ -DPMGR_MAIN -DDT_IO src/pmgr.c src/dt.c

clean:
	rm -f dt pmgr
