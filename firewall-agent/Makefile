CC = gcc
CFLAGS = -Wall -Wextra -I../shared

TARGET = firewall-agent
SRCS = main.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)
