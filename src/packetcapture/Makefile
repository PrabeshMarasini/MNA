CC = gcc
CFLAGS = -Wall -Wextra -pthread -lpcap
TARGET = arp_tool

# Build directory structure (at project root level)
BUILD_DIR = ../../build
BUILD_MAIN_DIR = $(BUILD_DIR)/src/packetcapture
BUILD_PROTOCOLS_DIR = $(BUILD_DIR)/src/protocols

# Main sources
MAIN_SOURCES = main.c arp.c protocol.c device_scanner.c

# Protocol analyzer sources
PROTOCOL_SOURCES = ../protocols/tcp/tcp.c \
                   ../protocols/udp/udp.c \
                   ../protocols/http/http.c \
                   ../protocols/ftp/ftp.c \
                   ../protocols/smtp/smtp.c \
                   ../protocols/ssh/ssh.c \
                   ../protocols/imap/imap.c \
                   ../protocols/snmp/snmp.c \
                   ../protocols/ipv4/ipv4.c \
                   ../protocols/ipv6/ipv6.c \
                   ../protocols/arp/arp.c \
                   ../protocols/dhcp/dhcp.c \
                   ../protocols/https/https.c \
                   ../protocols/quic/quic.c

# Object files with build directory paths
MAIN_OBJECTS = $(addprefix $(BUILD_MAIN_DIR)/, $(MAIN_SOURCES:.c=.o))
PROTOCOL_OBJECTS = $(BUILD_PROTOCOLS_DIR)/tcp.o \
                   $(BUILD_PROTOCOLS_DIR)/udp.o \
                   $(BUILD_PROTOCOLS_DIR)/http.o \
                   $(BUILD_PROTOCOLS_DIR)/ftp.o \
                   $(BUILD_PROTOCOLS_DIR)/smtp.o \
                   $(BUILD_PROTOCOLS_DIR)/ssh.o \
                   $(BUILD_PROTOCOLS_DIR)/imap.o \
                   $(BUILD_PROTOCOLS_DIR)/snmp.o \
                   $(BUILD_PROTOCOLS_DIR)/ipv4.o \
                   $(BUILD_PROTOCOLS_DIR)/ipv6.o \
                   $(BUILD_PROTOCOLS_DIR)/arp.o \
                   $(BUILD_PROTOCOLS_DIR)/dhcp.o \
                   $(BUILD_PROTOCOLS_DIR)/https.o \
                   $(BUILD_PROTOCOLS_DIR)/quic.o

ALL_OBJECTS = $(MAIN_OBJECTS) $(PROTOCOL_OBJECTS)

all: $(BUILD_DIR) $(TARGET)

# Create build directory structure
$(BUILD_DIR):
	@mkdir -p $(BUILD_MAIN_DIR)
	@mkdir -p $(BUILD_PROTOCOLS_DIR)
	@echo "Created build directory structure"

$(TARGET): $(ALL_OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(ALL_OBJECTS)
	@echo "Built $(TARGET) successfully"

# Main source compilation
$(BUILD_MAIN_DIR)/%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Protocol source compilation
$(BUILD_PROTOCOLS_DIR)/tcp.o: ../protocols/tcp/tcp.c
	@echo "Compiling TCP protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/udp.o: ../protocols/udp/udp.c
	@echo "Compiling UDP protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/http.o: ../protocols/http/http.c
	@echo "Compiling HTTP protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/ftp.o: ../protocols/ftp/ftp.c
	@echo "Compiling FTP protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/smtp.o: ../protocols/smtp/smtp.c
	@echo "Compiling SMTP protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/ssh.o: ../protocols/ssh/ssh.c
	@echo "Compiling SSH protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/imap.o: ../protocols/imap/imap.c
	@echo "Compiling IMAP protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/snmp.o: ../protocols/snmp/snmp.c
	@echo "Compiling SNMP protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/ipv4.o: ../protocols/ipv4/ipv4.c
	@echo "Compiling IPv4 protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/ipv6.o: ../protocols/ipv6/ipv6.c
	@echo "Compiling IPv6 protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/arp.o: ../protocols/arp/arp.c
	@echo "Compiling ARP protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/dhcp.o: ../protocols/dhcp/dhcp.c
	@echo "Compiling DHCP protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/https.o: ../protocols/https/https.c
	@echo "Compiling HTTPS/TLS protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_PROTOCOLS_DIR)/quic.o: ../protocols/quic/quic.c
	@echo "Compiling QUIC protocol analyzer..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning build files..."
	rm -rf $(BUILD_DIR) $(TARGET) test_protocols
	@echo "Clean complete"

rebuild: clean all

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	@echo "Installed $(TARGET) to /usr/local/bin/"

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled $(TARGET) from /usr/local/bin/"

# Test program (exclude main.o to avoid multiple main functions)
TEST_OBJECTS = $(BUILD_MAIN_DIR)/arp.o $(BUILD_MAIN_DIR)/protocol.o $(BUILD_MAIN_DIR)/device_scanner.o $(PROTOCOL_OBJECTS)
test_protocols: test_protocols.c $(TEST_OBJECTS)
	@echo "Building test program..."
	$(CC) $(CFLAGS) test_protocols.c $(TEST_OBJECTS) -o test_protocols

# Show build structure
show-structure:
	@echo "Build directory structure:"
	@find $(BUILD_DIR) -type f 2>/dev/null | sort || echo "No build files found"

.PHONY: all clean rebuild install uninstall show-structure