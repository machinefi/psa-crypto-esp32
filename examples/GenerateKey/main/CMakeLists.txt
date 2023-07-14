idf_component_register(SRCS "GenerateKey.c"
                    INCLUDE_DIRS ".")
                    
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")                  
