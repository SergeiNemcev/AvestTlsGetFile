#if !defined(AVCSPACTIVATOR_H)
#define AVCSPACTIVATOR_H

#ifdef AVCSPACTIVATOR_EXPORTS
#define AVCSPACTIVATOR_API __declspec(dllexport)
#else
#define AVCSPACTIVATOR_API __declspec(dllimport)
#endif

#define AVCSPACTIVATOR_CC _stdcall

extern "C"
{

AVCSPACTIVATOR_API void AVCSPACTIVATOR_CC
AvCSPActivateBAPB();

} // extern "C"

#endif // !defined(AVCSPACTIVATOR_H)
