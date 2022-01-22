add_contract(zsw.perms zsw.perms ${CMAKE_CURRENT_SOURCE_DIR}/src/zsw.perms.cpp)

target_include_directories(zsw.perms
   PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../zswcore/include)

set_target_properties(zsw.perms
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

#configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/ricardian/zsw.perms.contracts.md.in ${CMAKE_CURRENT_BINARY_DIR}/ricardian/zsw.perms.contracts.md @ONLY )

target_compile_options( zsw.perms PUBLIC -R${CMAKE_CURRENT_SOURCE_DIR}/ricardian -R${CMAKE_CURRENT_BINARY_DIR}/ricardian )
