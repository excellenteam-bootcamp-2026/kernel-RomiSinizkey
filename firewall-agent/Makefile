CC = gcc
CFLAGS = -Wall -Wextra

TARGET = firewall-agent
SRCS = main.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)
