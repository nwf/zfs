include $(top_srcdir)/config/Rules.am

# -Wnoformat-truncation to get rid of compiler warning for unchecked
#  truncating snprintfs on gcc 7.1.1.
AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN) $(NO_FORMAT_TRUNCATION)
AM_CPPFLAGS += -DDEBUG -UNDEBUG

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = ztest nwftest

ztest_SOURCES = \
	ztest.c

ztest_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzpool/libzpool.la

ztest_LDADD += -lm
ztest_LDFLAGS = -pthread

nwftest_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

nwftest_LDADD += -lm
nwftest_LDFLAGS = -pthread
