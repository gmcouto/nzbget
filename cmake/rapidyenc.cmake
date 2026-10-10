# NOTE — pinned-tag dependency on rapidyenc internals (see task F4.3):
# daemon/nntp/Decoder.cpp extern-declares rapidyenc's internal decoder kernel
# pointers (`RapidYenc::_do_decode`, `RapidYenc::_do_decode_raw`, `_decode_isa`,
# defined in rapidyenc's src/decoder.cc) to reach the incremental non-raw
# (no NNTP dot-unstuffing) decoder, which the public rapidyenc.h API does not
# expose (rapidyenc_decode_incremental is hardwired to is_raw=true). These
# internals are only known-good for the exact GIT_TAG pinned below
# (v1.1.1-20260914, RAPIDYENC_VERSION 0x010101 — guarded by static_assert in
# daemon/nntp/Decoder.cpp). If the tag is bumped and any of these internals
# changed (renamed pointers, changed YencDecoderState/YencDecoderEnd types or
# kernel signatures, altered the "consumes entire len input" non-raw contract),
# encrypted-article decoding breaks: at best a compile error in Decoder.cpp,
# at worst silent corruption of restored encrypted blocks. Re-validate the
# extern block against rapidyenc's src/decoder.cc on every bump, or until a
# public non-raw decode entry point exists upstream (draft issue:
# notes/rapidyenc-upstream-issue.md in the parent worktree).
set(RAPIDYENC_ROOT ${CMAKE_BINARY_DIR}/rapidyenc/src)
if(CMAKE_GENERATOR MATCHES "Visual Studio")
	set(RAPIDYENC_LIBS
		${RAPIDYENC_ROOT}/rapidyenc-build/rapidyenc_static/${CMAKE_BUILD_TYPE}/rapidyenc.lib
	)
elseif(CMAKE_GENERATOR MATCHES "Xcode")
	set(RAPIDYENC_LIBS
		${RAPIDYENC_ROOT}/rapidyenc-build/rapidyenc_static/${CMAKE_BUILD_TYPE}/librapidyenc.a
	)
else()
	set(RAPIDYENC_LIBS
		${RAPIDYENC_ROOT}/rapidyenc-build/rapidyenc_static/librapidyenc.a
	)
endif()

set(CMAKE_ARGS
	-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
	-DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}
	-DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
	-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
	-DDISABLE_SHARED=ON
	-DDISABLE_TOOL=ON
	-DDISABLE_ENCODE=ON
	-DDISABLE_DECODE=OFF
	-DDISABLE_CRC=OFF
	-DDISABLE_AVX256=OFF
	-DDISABLE_CRCUTIL=OFF
	-DUSE_SANITIZERS=${USE_SANITIZERS}
)

if(MSVC)
	set(CMAKE_ARGS ${CMAKE_ARGS}
		-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>
	)
endif()

if(DEFINED TOOLCHAIN_PREFIX)
	set(CMAKE_ARGS ${CMAKE_ARGS} -DTOOLCHAIN_PREFIX=${TOOLCHAIN_PREFIX})
endif()

if(APPLE)
	set(CMAKE_ARGS ${CMAKE_ARGS}
		-DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
	)
endif()

if(CMAKE_SYSROOT)
	set(CMAKE_ARGS ${CMAKE_ARGS}
		-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
		-DCMAKE_SYSROOT=${CMAKE_SYSROOT}
		-DCMAKE_CXX_FLAGS=-I${CMAKE_SYSROOT}/usr/include/c++/v1
	)
endif()

ExternalProject_add(
	rapidyenc
	PREFIX			rapidyenc
	GIT_REPOSITORY	https://github.com/nzbgetcom/rapidyenc.git
	GIT_TAG			v1.1.1-20260914
	TLS_VERIFY		TRUE
	GIT_SHALLOW		TRUE
	GIT_PROGRESS	TRUE
	DOWNLOAD_EXTRACT_TIMESTAMP	TRUE
	BUILD_BYPRODUCTS ${RAPIDYENC_LIBS}
	CMAKE_ARGS		 ${CMAKE_ARGS}
	INSTALL_COMMAND	""
)

set(LIBS ${LIBS} ${RAPIDYENC_LIBS})
set(INCLUDES ${INCLUDES} ${RAPIDYENC_ROOT}/rapidyenc)
