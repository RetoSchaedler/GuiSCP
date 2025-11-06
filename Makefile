CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
LIBS = `pkg-config --cflags --libs gtk+-3.0` -lssh
TARGET = guiscp
SRC = main.c

# Standard-Ziel
all: $(TARGET)

# Kompilieren
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# Clean
clean:
	rm -f $(TARGET)

# Installieren (optional)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Deinstallieren
uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall

