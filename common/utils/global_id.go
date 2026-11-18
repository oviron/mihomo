package utils

import (
	"hash/maphash"
	"unsafe"
)

var globalSeed = maphash.MakeSeed()

func GlobalID(material string) (id [8]byte) {
	if globalIDKey != nil {
		return keyedGlobalID(globalIDKey, material)
	}
	*(*uint64)(unsafe.Pointer(&id[0])) = maphash.String(globalSeed, material)
	return
}

func MapHash(material string) uint64 {
	return maphash.String(globalSeed, material)
}
