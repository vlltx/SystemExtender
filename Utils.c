#include "Kse.h"

PVOID RtlFindPattern(
	_In_ PVOID Source,
	_In_ SIZE_T SourceLength,
	_In_ PVOID Pattern,
	_In_ SIZE_T PatternLength
)
{
	SIZE_T Index;

	for (Index = 0; Index <= SourceLength - PatternLength; ++Index) {
		if (RtlCompareMemory((PUINT8)(Source)+Index, Pattern, PatternLength) == PatternLength) return (PUINT8)(Source)+Index;
	}

	return NULL;
}