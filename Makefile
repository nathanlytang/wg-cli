CC = gcc
CFLAGS  = -Wall -std=gnu99

# the build target executable:
TARGET = wg-cli

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $(TARGET).c -o $(TARGET) 

clean:
	$(RM) $(TARGET)