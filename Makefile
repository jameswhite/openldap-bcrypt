# $OpenLDAP$

LDAP_SRC = ../../../..
LDAP_BUILD = ../../../..
LDAP_INC = -I$(LDAP_BUILD)/include -I$(LDAP_SRC)/include -I$(LDAP_SRC)/servers/slapd -I./libbcrypt
LDAP_LIB = $(LDAP_BUILD)/libraries/libldap_r/libldap_r.la \
	$(LDAP_BUILD)/libraries/liblber/liblber.la

LIBTOOL = $(LDAP_BUILD)/libtool
CC = gcc
OPT = -g -O2 -Wall -fPIC
#DEFS = -DSLAPD_BCRYPT_DEBUG

INCS = $(LDAP_INC)
LIBS = $(LDAP_LIB)

PROGRAMS = pw-bcrypt.la
LTVER = 0:0:0

#prefix=/usr/local
prefix=`grep -e "^prefix =" $(LDAP_BUILD)/Makefile | cut -d= -f2`

exec_prefix=$(prefix)
ldap_subdir=/ldap

libdir=$(exec_prefix)/lib
libexecdir=$(exec_prefix)/lib
moduledir = $(libexecdir)$(ldap_subdir)

.SUFFIXES: .c .o .lo

.c.lo:
	$(LIBTOOL) --mode=compile $(CC) $(OPT) $(DEFS) $(INCS) -c $<

all: $(PROGRAMS)

pw-bcrypt.la: pw-bcrypt.lo libbcrypt/bcrypt.a
	$(LIBTOOL) --mode=link $(CC) $(OPT) -L./libbcrypt -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ -lbcrypt pw-bcrypt.lo $(LIBS)

libbcrypt/bcrypt.a:
	$(MAKE) -C libbcrypt

clean:
	$(MAKE) -C libbcrypt clean
	rm -rf *.o *.lo *.la .libs

install:	$(PROGRAMS)
	mkdir -p $(DESTDIR)$(moduledir)
	for p in $(PROGRAMS) ; do \
		$(LIBTOOL) --mode=install cp $$p $(DESTDIR)$(moduledir) ; \
	done

