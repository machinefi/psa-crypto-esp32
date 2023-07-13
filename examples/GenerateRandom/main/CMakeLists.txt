idf_component_register(SRCS "GenerateRandom.c"
                    INCLUDE_DIRS ".")
                    
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")                  
