#!/bin/sh

LIB_DEPS="/lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/librt.so.1 /lib/x86_64-linux-gnu/libgcc_s.so.1"
USR_LIB_DEPS="/usr/lib/x86_64-linux-gnu/libsodium.so.23 /usr/lib/x86_64-linux-gnu/libc++.so.1 /usr/lib/x86_64-linux-gnu/libc++abi.so.1"

BINS="/app/source/build/snell_server/snell-server"

PKGDIR="/app/pkg"

rm -rf $PKGDIR/*
mkdir -p $PKGDIR/lib $PKGDIR/usr/bin

cp $LIB_DEPS $PKGDIR/lib
cp $USR_LIB_DEPS $PKGDIR/lib
cp $BINS $PKGDIR/usr/bin

cd $PKGDIR

rm -f /app/pkg.tar
tar cf /app/pkg.tar ./

