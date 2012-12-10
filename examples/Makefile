
SOURCES:= rpl-root-node.c socket.c send.c recv.c util.c

OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))

PROGRAMS:=rpl-root-node

CFLAGS       = -g -I.. -D_GNU_SOURCE
LDFLAGS      = -L.. -L/usr/lib
LDLIBS       = -lrpl -lrt

#all:    $(PROGRAMS)

rpl-root-node: $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS) $(LDLIBS)

clean:
	rm $(OBJECTS) rpl-root-node
