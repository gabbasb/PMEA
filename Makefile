INCLUDES = -I$(shell /usr/local/pg12/bin/pg_config --includedir)
LIBPATH = -L$(shell /usr/local/pg12/bin/pg_config --libdir)
CFLAGS += $(INCLUDES) -g
LDFLAGS += -g
LDLIBS += $(LIBPATH) -lpq

CFLAGS += -I/usr/include/openssl/
LDFLAGS += -L/usr/lib64/
LDLIBS += -lcrypto -lm

pmea: pmea.o
