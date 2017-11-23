cmake_minimum_required(VERSION 2.8)
project (tunneldigger)

set(USE_LIBNL FALSE CACHE BOOL "Explicitly use libnl over libnl-tiny")
set(USE_LIBNL_TINY FALSE CACHE BOOL "Explicitly use libnl-tiny over libnl")

find_package(PkgConfig)

if(USE_LIBNL AND USE_LIBNL_TINY)
	message(FATAL_ERROR "libnl and libnl-tiny cannot be used together")
elseif(USE_LIBNL_TINY)
	pkg_check_modules(LIBNL REQUIRED libnl-tiny)
elseif(NOT USE_LIBNL)
	pkg_check_modules(LIBNL libnl-tiny)
endif()

if(NOT LIBNL_FOUND OR USE_LIBNL)
	pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)
endif()

pkg_check_modules(LIBASYNCNS libasyncns)
if(LIBASYNCNS_FOUND)
	add_definitions("-DUSE_SHARED_LIBASYNCNS=1")
	add_executable(tunneldigger l2tp_client.c)
else()
	add_executable(tunneldigger l2tp_client.c libasyncns/asyncns.c)
endif()

include_directories(
	${LIBASYNCNS_INCLUDE_DIRS}
	${LIBNL_INCLUDE_DIRS}
	${LIBNL_TINY_INCLUDE_DIRS}
)

target_link_libraries(tunneldigger
	${LIBASYNCNS_LIBRARIES}
	${LIBNL_LIBRARIES}
	${LIBNL_TINY_LIBRARIES}
	-lpthread
	-lresolv
	-lrt
)

install(TARGETS tunneldigger DESTINATION bin)
