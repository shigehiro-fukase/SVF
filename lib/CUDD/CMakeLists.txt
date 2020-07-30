set(SOURCES
	cuddTable.c
	cuddInit.c
	cuddAPI.c
	cuddRef.c
	cuddCheck.c
	cuddUtil.c
	cuddCof.c
	cuddSat.c
	cuddReorder.c
	cuddAddIte.c
	cuddBddIte.c
	cuddBddAbs.c
	cuddZddReord.c
	safe_mem.c
	mtrBasic.c
	mtrGroup.c
	cuddCache.c
	cuddLCache.c
	cuddInteract.c
	cuddGroup.c
	cuddAnneal.c
	cuddExact.c
	cuddGenetic.c
	cuddLinear.c
	cuddSymmetry.c
	cuddWindow.c
	cuddZddFuncs.c
	cuddZddGroup.c
	cuddZddIsop.c
	cuddZddSetop.c
	cuddZddLin.c
	cuddZddSymm.c
	datalimit.c
	cpu_time.c
	epd.c
	st.c
)

if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    add_llvm_library(Cudd ${SOURCES} LINK_LIBS m)
    target_link_libraries(Cudd m)
    set_target_properties(Cudd PROPERTIES COMPILE_FLAGS "-Wno-format -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast -O3 -w -DHAVE_IEEE_754 -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8")
else()
    add_llvm_library(Cudd ${SOURCES} LINK_LIBS)
    target_link_libraries(Cudd)
    set_target_properties(Cudd PROPERTIES COMPILE_FLAGS "/DSIZEOF_VOID_P=8 /DHAVE_SYS_TIME_H=0 /DHAVE_SYS_RESOURCE_H=0")
endif()

if(DEFINED IN_SOURCE_BUILD)
    add_dependencies(Cudd intrinsics_gen)
endif()
