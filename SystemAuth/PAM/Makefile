# Compile-only target. This does not install or enable a PAM rule.
CC ?= clang
CFLAGS ?= -O2 -Wall -Wextra -Werror -fstack-protector-strong -mmacosx-version-min=15.0

.PHONY: all clean
all: pam_faceid.so

pam_faceid.so: pam_faceid.c faceid_auth_protocol.h faceid_io.h
	$(CC) $(CFLAGS) -bundle -fPIC -o $@ pam_faceid.c -lpam

clean:
	rm -f pam_faceid.so
