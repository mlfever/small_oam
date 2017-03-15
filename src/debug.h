#include <stdio.h>

#define OAM_ENT(format,...) \
    printf(">> %s  %s  %5d: %s", __FILE__, __func__, __LINE__, format, ##__VA_ARGS__)

#define OAM_EXT(format,...) \
    printf("<< %s  %s  %5d: %s", __FILE__, __func__, __LINE__, format, ##__VA_ARGS__)


#define OAM_ERR(format,...) \
    printf("XX %s  %s  %5d: %s", __FILE__, __func__, __LINE__, format, ##__VA_ARGS__)


#define OAM_INFO(format,...) \
    printf("INFO %s  %s  %5d: %s", __FILE__, __func__, __LINE__, format, ##__VA_ARGS__)


#define OAM_WARN(format,...) \
    printf("WARN %s  %s  %5d: %s", __FILE__, __func__, __LINE__, format, ##__VA_ARGS__) 


