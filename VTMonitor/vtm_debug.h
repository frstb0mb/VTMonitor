#pragma once

#ifdef __DEBUG__
#define DebugVTMON(format, ...)  DebugPrint(format, ...)
#else
#define DebugVTMON(format, ...) 
#endif