# Compile-only transport probe. ALL requests receive UNAVAILABLE.
CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra -Werror -fstack-protector-strong -mmacosx-version-min=15.0

.PHONY: all clean
all: faceid-authd-probe

faceid-authd-probe: faceid_authd_probe.c ../PAM/faceid_auth_protocol.h ../PAM/faceid_io.h
	$(CC) $(CFLAGS) -o $@ faceid_authd_probe.c

clean:
	rm -f faceid-authd-probe
