include(FindPkgConfig)

if (PKG_CONFIG_FOUND)
	pkg_check_modules(SWScale libswscale)
endif()

find_path(SWScale_INCLUDE_DIR libswscale/swscale.h PATHS ${SWScale_INCLUDE_DIRS})

# Fix: if pkg-config found SWScale, but SWScale_LIBRARY is not defined,
# try to take the first .lib from SWScale_LIBRARIES (pkg-config returns the full path)
if(NOT SWScale_LIBRARY AND SWScale_LIBRARIES)
    list(GET SWScale_LIBRARIES 0 SWScale_LIBRARY)
endif()

find_library(SWScale_LIBRARY swscale PATHS ${SWScale_LIBRARY_DIRS})

FIND_PACKAGE_HANDLE_STANDARD_ARGS(SWScale DEFAULT_MSG SWScale_INCLUDE_DIR SWScale_LIBRARY)

mark_as_advanced(SWScale_INCLUDE_DIR SWScale_LIBRARY)

