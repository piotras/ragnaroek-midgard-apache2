#! /bin/sh

src_dir=`pwd`
configure_options="$@"

autoreconf -i 
automake

$src_dir/configure $configure_options

echo
echo "Run \`make\` to compile"
echo
