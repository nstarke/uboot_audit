dnl Local fallback macros for the vendored TPM2-TSS build.
dnl They keep autoreconf self-contained in this repository without requiring
dnl autoconf-archive or doxygen macro packages to be installed on the host.

AC_DEFUN([AX_IS_RELEASE], [
    ax_is_release=yes
    AC_SUBST([ax_is_release])
])

AC_DEFUN([AX_CHECK_ENABLE_DEBUG], [
    AC_ARG_ENABLE([debug],
        [AS_HELP_STRING([--enable-debug], [build TPM2-TSS with debug-friendly settings])],
        [enable_debug=$enableval],
        [enable_debug=no])
])

AC_DEFUN([AX_CHECK_COMPILE_FLAG], [
    ax_save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $1"
    AC_MSG_CHECKING([whether $CC supports $1])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])], [
        AC_MSG_RESULT([yes])
        CFLAGS="$ax_save_CFLAGS"
        $2
    ], [
        AC_MSG_RESULT([no])
        CFLAGS="$ax_save_CFLAGS"
        $3
    ])
])

AC_DEFUN([AX_CHECK_PREPROC_FLAG], [
    ax_save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $1"
    AC_MSG_CHECKING([whether the preprocessor supports $1])
    AC_PREPROC_IFELSE([AC_LANG_SOURCE([[int ela_dummy;]])], [
        AC_MSG_RESULT([yes])
        CPPFLAGS="$ax_save_CPPFLAGS"
        $2
    ], [
        AC_MSG_RESULT([no])
        CPPFLAGS="$ax_save_CPPFLAGS"
        $3
    ])
])

AC_DEFUN([AX_CHECK_LINK_FLAG], [
    ax_save_LDFLAGS="$LDFLAGS"
    LDFLAGS="$LDFLAGS $1"
    AC_MSG_CHECKING([whether the linker supports $1])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])], [
        AC_MSG_RESULT([yes])
        LDFLAGS="$ax_save_LDFLAGS"
        $2
    ], [
        AC_MSG_RESULT([no])
        LDFLAGS="$ax_save_LDFLAGS"
        $3
    ])
])

AC_DEFUN([AX_ADD_FORTIFY_SOURCE], [
    ADD_PREPROC_FLAG([-D_FORTIFY_SOURCE=2])
])

AC_DEFUN([AX_RECURSIVE_EVAL], [
    eval "$2=\"$1\""
    AC_SUBST([$2])
])

AC_DEFUN([AX_NORMALIZE_PATH], [
    :
])

AC_DEFUN([AX_VALGRIND_CHECK], [
    VALGRIND_CHECK_RULES=
    AC_SUBST([VALGRIND_CHECK_RULES])
])

AC_DEFUN([AX_CODE_COVERAGE], [
    CODE_COVERAGE_CFLAGS=
    CODE_COVERAGE_LIBS=
    CODE_COVERAGE_RULES=
    AC_SUBST([CODE_COVERAGE_CFLAGS])
    AC_SUBST([CODE_COVERAGE_LIBS])
    AC_SUBST([CODE_COVERAGE_RULES])
])

AC_DEFUN([AX_ADD_AM_MACRO_STATIC], [
    :
])

AC_DEFUN([DX_DOXYGEN_FEATURE], [:])
AC_DEFUN([DX_DOT_FEATURE], [:])
AC_DEFUN([DX_HTML_FEATURE], [:])
AC_DEFUN([DX_CHM_FEATURE], [:])
AC_DEFUN([DX_CHI_FEATURE], [:])
AC_DEFUN([DX_MAN_FEATURE], [:])
AC_DEFUN([DX_RTF_FEATURE], [:])
AC_DEFUN([DX_XML_FEATURE], [:])
AC_DEFUN([DX_PDF_FEATURE], [:])
AC_DEFUN([DX_PS_FEATURE], [:])

AC_DEFUN([DX_INIT_DOXYGEN], [
    DX_RULES=
    DX_CLEANFILES=
    DX_FLAG_doc=0
    enable_doxygen_doc=no
    AC_SUBST([DX_RULES])
    AC_SUBST([DX_CLEANFILES])
    AC_SUBST([DX_FLAG_doc])
    AC_SUBST([enable_doxygen_doc])
])
