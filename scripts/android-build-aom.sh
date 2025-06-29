#!/bin/bash
set -x

SCM_URL=https://aomedia.googlesource.com/aom
SCM_TAG=v3.9.1
SCM_HASH=d89daa160a0ea1409c4193be5b17c9591024c4f5a0e545dcb9d197535c66836e

COMPILER=4.9

source $(dirname "${BASH_SOURCE[0]}")/android-build-common.sh

function build {
  if [ $# -ne 2 ]; then
    echo "Invalid arguments $@"
    exit 1
  fi

  CONFIG=$1
  DST_PREFIX=$2

  common_run export CC=clang
  common_run export PATH=$(${SCRIPT_PATH}/toolchains_path.py --ndk ${ANDROID_NDK}):$ORG_PATH
  common_run export ANDROID_NDK=${ANDROID_NDK}
  common_run export ANDROID_NDK_ROOT=${ANDROID_NDK}
  common_run export ANDROID_NDK_HOME=${ANDROID_NDK}

  echo "CONFIG=$CONFIG"
  echo "DST_PREFIX=$DST_PREFIX"
  echo "PATH=$PATH"

  BASE=$(pwd)
  DST_DIR=$BUILD_DST/$DST_PREFIX
  common_run cd $BUILD_SRC

  # Создаём отдельный build-каталог для out-of-source сборки
  BUILD_DIR=build-$DST_PREFIX
  common_run rm -rf $BUILD_DIR
  common_run mkdir $BUILD_DIR
  common_run cd $BUILD_DIR

  # Конфигурируем cmake для нужной архитектуры
  common_run cmake .. -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=$CONFIG \
    -DANDROID_PLATFORM=android-$NDK_TARGET \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_TESTS=OFF \
    -DENABLE_EXAMPLES=OFF

  common_run make -j$(nproc)

  if [ ! -d $DST_DIR ]; then
    common_run mkdir -p $DST_DIR
  fi

  # Копируем собранные библиотеки
  common_run cp *.a $DST_DIR/ 2>/dev/null || true
  common_run cd $BASE
}

# Run the main program.
common_parse_arguments $@

SCM_MOD_TAG=$SCM_TAG

common_update_git $SCM_URL $SCM_MOD_TAG $BUILD_SRC $SCM_HASH

ORG_PATH=$PATH
for ARCH in $BUILD_ARCH; do

  case $ARCH in
  "armeabi-v7a")
    build "armeabi-v7a" "armeabi-v7a"
    ;;
  "x86")
    build "x86" "x86"
    ;;
  "arm64-v8a")
    build "arm64-v8a" "arm64-v8a"
    ;;
  "x86_64")
    build "x86_64" "x86_64"
    ;;
  *)
    echo "[WARNING] Skipping unsupported architecture $ARCH"
    continue
    ;;
  esac

  # Перемещаем создание include-директории и копирование заголовков внутрь цикла
  if [ ! -d $BUILD_DST/$ARCH/include ]; then
    common_run mkdir -p $BUILD_DST/$ARCH/include
  fi
  if [ -d $BUILD_SRC/include/aom ]; then
    common_run cp -L -R $BUILD_SRC/include/aom $BUILD_DST/$ARCH/include/
  else
    echo "[WARNING] $BUILD_SRC/include/aom not found, headers not copied for $ARCH"
  fi
done
