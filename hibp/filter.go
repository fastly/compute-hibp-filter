package hibp

import (
	"bufio"
	"compute-hibp-filter/config"
	"encoding/binary"
	"log"

	"github.com/FastFilter/xorfilter"
	"github.com/dgryski/go-metro"
)

func writeUint32ToBufioWriter(w *bufio.Writer, value uint32) {
	bytes4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes4, value)
	_, err := w.Write(bytes4)
	if err != nil {
		log.Fatalln("Error writing uint32 to writer: ", err.Error())
		return
	}
}

func CreateFilterWithHashes(prefix string, hashes []string) *xorfilter.BinaryFuse8 {

	keys_for_prefix := make([]uint64, 0)
	for _, hash := range hashes {
		key_value := metro.Hash64([]byte(hash), config.METRO_HASH_SEED)
		keys_for_prefix = append(keys_for_prefix, key_value)
	}
	filter, err := xorfilter.PopulateBinaryFuse8(keys_for_prefix)
	if err != nil {
		log.Fatal("Error creating filter for prefix "+prefix, err)
	}

	return filter
}

func WriteFilterToWriter(filter *xorfilter.BinaryFuse8, w *bufio.Writer) {

	// Write filter to writer
	bytes8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes8, filter.Seed)
	_, err := w.Write(bytes8)
	if err != nil {
		log.Fatalln("Error writing seed to writer: ", err.Error())
		return
	}

	writeUint32ToBufioWriter(w, filter.SegmentLength)
	writeUint32ToBufioWriter(w, filter.SegmentLengthMask)
	writeUint32ToBufioWriter(w, filter.SegmentCount)
	writeUint32ToBufioWriter(w, filter.SegmentCountLength)

	_, err = w.Write(filter.Fingerprints)
	if err != nil {
		log.Fatalln("Error writing fingerprints to writer: ", err.Error())
		return
	}
	w.Flush()
}

func DecodeXORFilter(data []byte) *xorfilter.BinaryFuse8 {
	seed := binary.LittleEndian.Uint64(data[0:8])
	segment_length := binary.LittleEndian.Uint32(data[8:12])
	segment_length_mask := binary.LittleEndian.Uint32(data[12:16])
	segment_count := binary.LittleEndian.Uint32(data[16:20])
	segment_count_length := binary.LittleEndian.Uint32(data[20:24])
	var fingerprints []uint8 = data[24:]

	return &xorfilter.BinaryFuse8{
		Seed:               seed,
		SegmentLength:      segment_length,
		SegmentLengthMask:  segment_length_mask,
		SegmentCount:       segment_count,
		SegmentCountLength: segment_count_length,
		Fingerprints:       fingerprints,
	}
}
