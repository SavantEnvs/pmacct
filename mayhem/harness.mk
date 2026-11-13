# Compile rules for the fuzz harnesses, run from the sanitized build's src/ directory by mayhem/build.sh.
# Reuses the project's own compile flags (DEFS, INCLUDES, CFLAGS, ...) from the automake-generated Makefile.
include Makefile

harness_%.o: $(srcdir)/../mayhem/harness_%.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# nfacctd's collector code lives in its main translation unit; rename main() so a harness can link it.
nfacctd_lib.o: $(srcdir)/nfacctd.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(CFLAGS) -Dmain=nfacctd_main -c $< -o $@
