#!/bin/bash 

type=$1


if [ "$type" == "debug" ]; then
    meson setup build-debug \
        -Dbuildtype=debug \
        -Db_lto=false
    ninja -C build-debug

elif [ "$type" == "debug-asan" ]; then
    meson setup build-debug-asan \
        -Dbuildtype=debug \
        -Db_sanitize=address \
        -Db_lto=false
    ninja -C build-debug-asan

elif [ "$type" == "release-syms" ]; then
    # No buildtype here, use optimization/debug/strip directly
    meson setup build-release-syms \
        -Doptimization=3 \
        -Ddebug=true \
        -Dstrip=false \
        -Db_lto=true
    ninja -C build-release-syms

elif [ "$type" == "release" ]; then
    meson setup build-release \
        -Dbuildtype=release \
        -Db_lto=true
    ninja -C build-release

elif [ "$type" == "all" ]; then
    meson setup build-debug \
        -Dbuildtype=debug \
        -Db_lto=false
    ninja -C build-debug

    meson setup build-debug-asan \
        -Dbuildtype=debug \
        -Db_sanitize=address \
        -Db_lto=false
    ninja -C build-debug-asan

    meson setup build-release-syms \
        -Doptimization=3 \
        -Ddebug=true \
        -Dstrip=false \
        -Db_lto=true
    ninja -C build-release-syms

    meson setup build-release \
        -Dbuildtype=release \
        -Db_lto=true
    ninja -C build-release


elif [ "$type" == "clean" ]; then
    rm -rf build*

#test commands 
elif [ "$type" == "debug-test" ]; then 
    meson test -C build-debug

elif [ "$type" == "debug-asan-test" ]; then 
    meson test -C build-debug-asan

elif [ "$type" == "release-syms-test" ]; then 
    meson test -C build-release-syms

elif [ "$type" == "release-test" ]; then
    meson test -C build-release

else
    echo "Usage: $0 [debug|debug-asan|release-syms|release|all|clean]"
    exit 1
fi