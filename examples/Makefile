
SOURCES:= rpl-root-node.c

OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))

PROGRAMS:=rpl-root-node

CFLAGS       = -g -I..
LDFLAGS      = -L.. -L/usr/lib
LDLIBS       = -lrpl -lrt

#all:    $(PROGRAMS)

rpl-root-node: rpl-root-node.o
	$(CC) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm $(OBJECTS) rpl-root-node
