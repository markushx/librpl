PACKAGE_VERSION:=0.1

SOURCES:= rpl.c rpl-dag.c rpl-icmp6.c rpl-timers.c rpl-of-etx.c	\
          rpl-ext-header.c rpl-debug.c

OBJECTS:= $(patsubst %.c, %.o, $(SOURCES))
HEADERS:= rpl-conf.h rpl.h rpl-private.h config.h

SUBDIRS:=examples

SHELL = /bin/sh
CC    = gcc

CFLAGS       = -fPIC -g
LDFLAGS      = -shared

TARGET  = librpl.so

all: $(TARGET) dirs

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJECTS)

clean: $(SUBDIRS)
	rm $(OBJECTS)
	for dir in $^; do \
		$(MAKE) -C $$dir clean; \
	done

dirs: $(SUBDIRS)
	for dir in $^; do \
		$(MAKE) -C $$dir ; \
	done
