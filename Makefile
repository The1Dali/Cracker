CC      = gcc
CFLAGS  = -Wall -Wextra -g -O2
LDFLAGS = -lssl -lcrypto

SRCS = main.c hash.c hashfile.c attack.c output.c
OBJS = $(SRCS:.c=.o)
TARGET = cracker

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)