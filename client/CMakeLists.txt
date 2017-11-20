cmake_minimum_required(VERSION 2.8)
project (tunneldigger)

find_package(PkgConfig)

pkg_check_modules(LIBNL libnl-3.0 libnl-genl-3.0)
if(NOT LIBNL_FOUND)
    pkg_check_modules(LIBNL REQUIRED libnl-tiny)
endif()

pkg_check_modules(LIBASYNCNS libasyncns)
if(LIBASYNCNS_FOUND)
	ADD_DEFINITIONS("-DUSE_SHARED_LIBASYNCNS=1")
	add_executable(tunneldigger l2tp_client.c)
else()
	add_executable(tunneldigger l2tp_client.c libasyncns/asyncns.c)
endif()

INCLUDE_DIRECTORIES(
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

INSTALL(TARGETS tunneldigger DESTINATION bin)
