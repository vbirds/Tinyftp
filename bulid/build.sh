#!/bin/bash

SRCDIR="../src/"
BINDIR="../bin/"

cd $SRCDIR &&
make -f makefile &&
mv ./*.o  $BINDIR && mv ./tinyftpd $BINDIR

