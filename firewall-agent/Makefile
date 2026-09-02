CC = gcc
CFLAGS = -Wall -Wextra -I../shared $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)
LDLIBS = $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0)

TARGET = firewall-agent
SRCS = main.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)
