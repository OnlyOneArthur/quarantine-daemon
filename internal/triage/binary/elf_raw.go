package binary

import (
	"encoding/binary"
	"errors"
)

func parseRawELFHeaders(data []byte, analysis *ELFAnalysis) error {
	if len(data) < 16 {
		return ErrELFTruncated
	}

	var byteOrder binary.ByteOrder
	switch data[5] {
	case 1:
		byteOrder = binary.LittleEndian
	case 2:
		byteOrder = binary.BigEndian
	default:
		return errors.New("unknown ELF endianness")
	}

	switch data[4] {
	case 1: // 32-bit
		return parseELF32Headers(data, byteOrder, analysis)
	case 2: // 64-bit
		return parseELF64Headers(data, byteOrder, analysis)
	default:
		return errors.New("unknown ELF class")
	}
}

func processProgHeader(pType, pFlags uint32, pOffset, pFilesz uint64, data []byte, analysis *ELFAnalysis) {
	switch pType {
	case 1: // PT_LOAD
		analysis.HasValidPTLoad = true

		if pFlags&1 != 0 && !analysis.TextSectionFound { // PF_X
			if pFilesz > 0 && pOffset <= uint64(len(data)) && pFilesz <= uint64(len(data))-pOffset {
				analysis.TextEntropy = CalculateEntropy(data[pOffset : pOffset+pFilesz])
				analysis.TextSectionFound = true
			}
		}

		if (pFlags & 3) == 3 { // PF_X | PF_W
			analysis.HasRWXSegments = true
		}
	case 0x6474e551: // PT_GNU_STACK
		if pFlags&1 != 0 { // PF_X
			analysis.HasExecutableStack = true
		}
	}
}

func parseELF32Headers(data []byte, byteOrder binary.ByteOrder, analysis *ELFAnalysis) error {
	if len(data) < 52 {
		return ErrELFTruncated
	}
	phoff := uint64(byteOrder.Uint32(data[28:32]))
	shoff := uint64(byteOrder.Uint32(data[32:36]))
	phentsize := int(byteOrder.Uint16(data[42:44]))
	phnum := int(byteOrder.Uint16(data[44:46]))
	shentsize := int(byteOrder.Uint16(data[46:48]))
	shnum := int(byteOrder.Uint16(data[48:50]))

	if phnum > 0 && phoff > 0 && phentsize >= 32 {
		for i := range phnum {
			poff := phoff + uint64(i)*uint64(phentsize)
			if poff < phoff || poff+32 < poff || poff+32 > uint64(len(data)) {
				break
			}
			off := int(poff)
			pType := byteOrder.Uint32(data[off : off+4])
			pOffset := uint64(byteOrder.Uint32(data[off+4 : off+8]))
			pFilesz := uint64(byteOrder.Uint32(data[off+16 : off+20]))
			pFlags := byteOrder.Uint32(data[off+24 : off+28])
			processProgHeader(pType, pFlags, pOffset, pFilesz, data, analysis)
		}
	}

	if analysis.HasValidPTLoad && sectionTableInvalid(shoff, shnum, shentsize, len(data)) {
		analysis.CorruptedSectionHeaders = true
	}
	return nil
}

func parseELF64Headers(data []byte, byteOrder binary.ByteOrder, analysis *ELFAnalysis) error {
	if len(data) < 64 {
		return ErrELFTruncated
	}
	phoff := byteOrder.Uint64(data[32:40])
	shoff := byteOrder.Uint64(data[40:48])
	phentsize := int(byteOrder.Uint16(data[54:56]))
	phnum := int(byteOrder.Uint16(data[56:58]))
	shentsize := int(byteOrder.Uint16(data[58:60]))
	shnum := int(byteOrder.Uint16(data[60:62]))

	if phnum > 0 && phoff > 0 && phentsize >= 56 {
		for i := range phnum {
			poff := phoff + uint64(i)*uint64(phentsize)
			if poff < phoff || poff+56 < poff || poff+56 > uint64(len(data)) {
				break
			}
			off := int(poff)
			pType := byteOrder.Uint32(data[off : off+4])
			pFlags := byteOrder.Uint32(data[off+4 : off+8])
			pOffset := byteOrder.Uint64(data[off+8 : off+16])
			pFilesz := byteOrder.Uint64(data[off+32 : off+40])
			processProgHeader(pType, pFlags, pOffset, pFilesz, data, analysis)
		}
	}

	if analysis.HasValidPTLoad && sectionTableInvalid(shoff, shnum, shentsize, len(data)) {
		analysis.CorruptedSectionHeaders = true
	}
	return nil
}

func sectionTableInvalid(shoff uint64, shnum, shentsize, dataLen int) bool {
	if shoff == 0 || shoff > uint64(dataLen) || shnum == 0 || shentsize <= 0 {
		return true
	}
	return uint64(shnum)*uint64(shentsize) > uint64(dataLen)-shoff
}
