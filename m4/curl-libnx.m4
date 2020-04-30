#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
#***************************************************************************

AC_DEFUN([CURL_WITH_LIBNX], [
dnl ----------------------------------------------------
dnl check for libnx
dnl ----------------------------------------------------

if test "x$OPT_LIBNX" != xno; then
  _cppflags=$CPPFLAGS
  _ldflags=$LDFLAGS
  ssl_msg=

  if test X"$OPT_LIBNX" != Xno; then

    if test "$OPT_LIBNX" = "yes"; then
      OPT_LIBNX=""
    fi

    if test -z "$OPT_LIBNX" ; then
      dnl check for lib first without setting any new path

      AC_CHECK_LIB(nx, sslInitialize,
      dnl libnx found, set the variable
       [
         AC_DEFINE(USE_LIBNX, 1, [if libnx is enabled])
         AC_SUBST(USE_LIBNX, [1])
         LIBNX_ENABLED=1
         USE_LIBNX="yes"
         ssl_msg="libnx"
	 test libnx != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
        ], [], -lnx)
    fi

    addld=""
    addlib=""
    addcflags=""
    libnx=""

    if test "x$USE_LIBNX" != "xyes"; then
      dnl add the path and test again
      addld=-L$OPT_LIBNX/lib$libsuff
      addcflags=-I$OPT_LIBNX/include
      libnx=$OPT_LIBNX/lib$libsuff

      LDFLAGS="$LDFLAGS $addld"
      if test "$addcflags" != "-I/usr/include"; then
         CPPFLAGS="$CPPFLAGS $addcflags"
      fi

      AC_CHECK_LIB(nx, sslInitialize,
       [
       AC_DEFINE(USE_LIBNX, 1, [if libnx is enabled])
       AC_SUBST(USE_LIBNX, [1])
       LIBNX_ENABLED=1
       USE_LIBNX="yes"
       ssl_msg="libnx"
       test libnx != "$DEFAULT_SSL_BACKEND" || VALID_DEFAULT_SSL_BACKEND=yes
       ],
       [
         CPPFLAGS=$_cppflags
         LDFLAGS=$_ldflags
       ], -lnx)
    fi

    if test "x$USE_LIBNX" = "xyes"; then
      AC_MSG_NOTICE([detected libnx])

      LIBS="-lnx $LIBS"
    fi

  fi dnl libnx not disabled

  test -z "$ssl_msg" || ssl_backends="${ssl_backends:+$ssl_backends, }$ssl_msg"
fi
])
