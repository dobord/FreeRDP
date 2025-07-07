# Installing Visual Studio 2022 Environment
& "E:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

# Setting up environment variables for the package manager to work
$env:PKG_CONFIG_PATH = "C:\ffmpeg\lib\pkgconfig"
$env:PKG_CONFIG = "C:\pkg-config\pkg-config.exe"

# Clear build folder
Remove-Item -LiteralPath "build" -Force -Recurse

# Configuring the build
cmake -S .. -B ../build-win64-msvc -DMONOLITHIC_BUILD=ON -DBUILD_SHARED_LIBS=OFF -G "Visual Studio 17 2022" -DMSVC_RUNTIME=static -DWITH_SSE2=ON -DOPENSSL_ROOT_DIR="E:\Qt\Qt6\Tools\OpenSSLv3\Win_x64" -DDEFINE_NO_DEPRECATED=ON -DWITH_FFMPEG=ON -DWITH_SWSCALE=ON -DWITH_DSP_FFMPEG=ON -DCHANNEL_URBDRC=OFF -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DWITH_CLIENT=ON -DWITH_SERVER=OFF -DWITH_SAMPLE=OFF -DSWScale_LIBRARY="C:/ffmpeg/lib/libswscale.lib" -DAVCODEC_LIBRARY="C:/ffmpeg/lib/libavcodec.lib" -DAVUTIL_LIBRARY="C:/ffmpeg/lib/libavutil.lib" -DSWRESAMPLE_LIBRARY="C:/ffmpeg/lib/libswresample.lib" -DCMAKE_STATIC_LINKER_FLAGS=" C:/ffmpeg/lib/libswscale.lib C:/ffmpeg/lib/libavcodec.lib C:/ffmpeg/lib/libavutil.lib C:/ffmpeg/lib/libswresample.lib mfuuid.lib ole32.lib strmiids.lib user32.lib bcrypt.lib"

# Compile the project
cmake --build build --config Release
