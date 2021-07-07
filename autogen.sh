#! /bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

set -x -e
mkdir -p m4
# --no-recursive is available only in recent autoconf versions
autoreconf -fv --install
