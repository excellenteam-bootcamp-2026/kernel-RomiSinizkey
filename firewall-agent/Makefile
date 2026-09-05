CC = gcc
PKGS = libnl-3.0 libnl-genl-3.0 libcurl libcjson
CFLAGS = -Wall -Wextra -I../shared $(shell pkg-config --cflags $(PKGS))
LDLIBS = $(shell pkg-config --libs $(PKGS))

TARGET = firewall-agent
SRCS = main.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)
