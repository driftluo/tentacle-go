// Generated by Molecule 0.7.2
// Generated by Moleculec-Go 0.1.9

package protocol_select

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

type Number uint32

const HeaderSizeUint uint32 = 4

// Byte is the primitive type
type Byte [1]byte

func NewByte(b byte) Byte {
	return Byte([1]byte{b})
}
func ByteDefault() Byte {
	return Byte([1]byte{0})
}
func ByteFromSliceUnchecked(slice []byte) *Byte {
	b := new(Byte)
	b[0] = slice[0]
	return b
}
func (b *Byte) AsSlice() []byte {
	return b[:]
}
func ByteFromSlice(slice []byte, _compatible bool) (*Byte, error) {
	if len(slice) != 1 {
		return nil, errors.New("TotalSizeNotMatch")
	}
	b := new(Byte)
	b[0] = slice[0]
	return b, nil
}
func unpackNumber(b []byte) Number {
	bytesBuffer := bytes.NewBuffer(b)
	var x Number
	binary.Read(bytesBuffer, binary.LittleEndian, &x)
	return x
}
func packNumber(num Number) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(num))
	return b
}

type StringBuilder struct {
	inner []Byte
}

func (s *StringBuilder) Build() String {
	size := packNumber(Number(len(s.inner)))

	b := new(bytes.Buffer)

	b.Write(size)
	len := len(s.inner)
	for i := 0; i < len; i++ {
		b.Write(s.inner[i].AsSlice())
	}

	sb := String{inner: b.Bytes()}

	return sb
}

func (s *StringBuilder) Set(v []Byte) *StringBuilder {
	s.inner = v
	return s
}
func (s *StringBuilder) Push(v Byte) *StringBuilder {
	s.inner = append(s.inner, v)
	return s
}
func (s *StringBuilder) Extend(iter []Byte) *StringBuilder {
	for i := 0; i < len(iter); i++ {
		s.inner = append(s.inner, iter[i])
	}
	return s
}
func (s *StringBuilder) Replace(index uint, v Byte) *Byte {
	if uint(len(s.inner)) > index {
		a := s.inner[index]
		s.inner[index] = v
		return &a
	}
	return nil
}

func NewStringBuilder() *StringBuilder {
	return &StringBuilder{[]Byte{}}
}

type String struct {
	inner []byte
}

func StringFromSliceUnchecked(slice []byte) *String {
	return &String{inner: slice}
}
func (s *String) AsSlice() []byte {
	return s.inner
}

func StringDefault() String {
	return *StringFromSliceUnchecked([]byte{0, 0, 0, 0})
}

func StringFromSlice(slice []byte, _compatible bool) (*String, error) {
	sliceLen := len(slice)
	if sliceLen < int(HeaderSizeUint) {
		errMsg := strings.Join([]string{"HeaderIsBroken", "String", strconv.Itoa(int(sliceLen)), "<", strconv.Itoa(int(HeaderSizeUint))}, " ")
		return nil, errors.New(errMsg)
	}
	itemCount := unpackNumber(slice)
	if itemCount == 0 {
		if sliceLen != int(HeaderSizeUint) {
			errMsg := strings.Join([]string{"TotalSizeNotMatch", "String", strconv.Itoa(int(sliceLen)), "!=", strconv.Itoa(int(HeaderSizeUint))}, " ")
			return nil, errors.New(errMsg)
		}
		return &String{inner: slice}, nil
	}
	totalSize := int(HeaderSizeUint) + int(1*itemCount)
	if sliceLen != totalSize {
		errMsg := strings.Join([]string{"TotalSizeNotMatch", "String", strconv.Itoa(int(sliceLen)), "!=", strconv.Itoa(int(totalSize))}, " ")
		return nil, errors.New(errMsg)
	}
	return &String{inner: slice}, nil
}

func (s *String) TotalSize() uint {
	return uint(HeaderSizeUint) + 1*s.ItemCount()
}
func (s *String) ItemCount() uint {
	number := uint(unpackNumber(s.inner))
	return number
}
func (s *String) Len() uint {
	return s.ItemCount()
}
func (s *String) IsEmpty() bool {
	return s.Len() == 0
}

// if *Byte is nil, index is out of bounds
func (s *String) Get(index uint) *Byte {
	var re *Byte
	if index < s.Len() {
		start := uint(HeaderSizeUint) + 1*index
		end := start + 1
		re = ByteFromSliceUnchecked(s.inner[start:end])
	}
	return re
}

func (s *String) RawData() []byte {
	return s.inner[HeaderSizeUint:]
}

func (s *String) AsBuilder() StringBuilder {
	size := s.ItemCount()
	t := NewStringBuilder()
	for i := uint(0); i < size; i++ {
		t.Push(*s.Get(i))
	}
	return *t
}

type StringVecBuilder struct {
	inner []String
}

func (s *StringVecBuilder) Build() StringVec {
	itemCount := len(s.inner)

	b := new(bytes.Buffer)

	// Empty dyn vector, just return size's bytes
	if itemCount == 0 {
		b.Write(packNumber(Number(HeaderSizeUint)))
		return StringVec{inner: b.Bytes()}
	}

	// Calculate first offset then loop for rest items offsets
	totalSize := HeaderSizeUint * uint32(itemCount+1)
	offsets := make([]uint32, 0, itemCount)
	offsets = append(offsets, totalSize)
	for i := 1; i < itemCount; i++ {
		totalSize += uint32(len(s.inner[i-1].AsSlice()))
		offsets = append(offsets, offsets[i-1]+uint32(len(s.inner[i-1].AsSlice())))
	}
	totalSize += uint32(len(s.inner[itemCount-1].AsSlice()))

	b.Write(packNumber(Number(totalSize)))

	for i := 0; i < itemCount; i++ {
		b.Write(packNumber(Number(offsets[i])))
	}

	for i := 0; i < itemCount; i++ {
		b.Write(s.inner[i].AsSlice())
	}

	return StringVec{inner: b.Bytes()}
}

func (s *StringVecBuilder) Set(v []String) *StringVecBuilder {
	s.inner = v
	return s
}
func (s *StringVecBuilder) Push(v String) *StringVecBuilder {
	s.inner = append(s.inner, v)
	return s
}
func (s *StringVecBuilder) Extend(iter []String) *StringVecBuilder {
	for i := 0; i < len(iter); i++ {
		s.inner = append(s.inner, iter[i])
	}
	return s
}
func (s *StringVecBuilder) Replace(index uint, v String) *String {
	if uint(len(s.inner)) > index {
		a := s.inner[index]
		s.inner[index] = v
		return &a
	}
	return nil
}

func NewStringVecBuilder() *StringVecBuilder {
	return &StringVecBuilder{[]String{}}
}

type StringVec struct {
	inner []byte
}

func StringVecFromSliceUnchecked(slice []byte) *StringVec {
	return &StringVec{inner: slice}
}
func (s *StringVec) AsSlice() []byte {
	return s.inner
}

func StringVecDefault() StringVec {
	return *StringVecFromSliceUnchecked([]byte{4, 0, 0, 0})
}

func StringVecFromSlice(slice []byte, compatible bool) (*StringVec, error) {
	sliceLen := len(slice)

	if uint32(sliceLen) < HeaderSizeUint {
		errMsg := strings.Join([]string{"HeaderIsBroken", "StringVec", strconv.Itoa(int(sliceLen)), "<", strconv.Itoa(int(HeaderSizeUint))}, " ")
		return nil, errors.New(errMsg)
	}

	totalSize := unpackNumber(slice)
	if Number(sliceLen) != totalSize {
		errMsg := strings.Join([]string{"TotalSizeNotMatch", "StringVec", strconv.Itoa(int(sliceLen)), "!=", strconv.Itoa(int(totalSize))}, " ")
		return nil, errors.New(errMsg)
	}

	if uint32(sliceLen) == HeaderSizeUint {
		return &StringVec{inner: slice}, nil
	}

	if uint32(sliceLen) < HeaderSizeUint*2 {
		errMsg := strings.Join([]string{"TotalSizeNotMatch", "StringVec", strconv.Itoa(int(sliceLen)), "<", strconv.Itoa(int(HeaderSizeUint * 2))}, " ")
		return nil, errors.New(errMsg)
	}

	offsetFirst := unpackNumber(slice[HeaderSizeUint:])
	if uint32(offsetFirst)%HeaderSizeUint != 0 || uint32(offsetFirst) < HeaderSizeUint*2 {
		errMsg := strings.Join([]string{"OffsetsNotMatch", "StringVec", strconv.Itoa(int(offsetFirst % 4)), "!= 0", strconv.Itoa(int(offsetFirst)), "<", strconv.Itoa(int(HeaderSizeUint * 2))}, " ")
		return nil, errors.New(errMsg)
	}

	if sliceLen < int(offsetFirst) {
		errMsg := strings.Join([]string{"HeaderIsBroken", "StringVec", strconv.Itoa(int(sliceLen)), "<", strconv.Itoa(int(offsetFirst))}, " ")
		return nil, errors.New(errMsg)
	}
	itemCount := uint32(offsetFirst)/HeaderSizeUint - 1

	offsets := make([]uint32, itemCount)

	for i := 0; i < int(itemCount); i++ {
		offsets[i] = uint32(unpackNumber(slice[HeaderSizeUint:][int(HeaderSizeUint)*i:]))
	}

	offsets = append(offsets, uint32(totalSize))

	for i := 0; i < len(offsets); i++ {
		if i&1 != 0 && offsets[i-1] > offsets[i] {
			errMsg := strings.Join([]string{"OffsetsNotMatch", "StringVec"}, " ")
			return nil, errors.New(errMsg)
		}
	}

	for i := 0; i < len(offsets); i++ {
		if i&1 != 0 {
			start := offsets[i-1]
			end := offsets[i]
			_, err := StringFromSlice(slice[start:end], compatible)

			if err != nil {
				return nil, err
			}
		}
	}

	return &StringVec{inner: slice}, nil
}

func (s *StringVec) TotalSize() uint {
	return uint(unpackNumber(s.inner))
}
func (s *StringVec) ItemCount() uint {
	var number uint = 0
	if uint32(s.TotalSize()) == HeaderSizeUint {
		return number
	}
	number = uint(unpackNumber(s.inner[HeaderSizeUint:]))/4 - 1
	return number
}
func (s *StringVec) Len() uint {
	return s.ItemCount()
}
func (s *StringVec) IsEmpty() bool {
	return s.Len() == 0
}

// if *String is nil, index is out of bounds
func (s *StringVec) Get(index uint) *String {
	var b *String
	if index < s.Len() {
		start_index := uint(HeaderSizeUint) * (1 + index)
		start := unpackNumber(s.inner[start_index:])

		if index == s.Len()-1 {
			b = StringFromSliceUnchecked(s.inner[start:])
		} else {
			end_index := start_index + uint(HeaderSizeUint)
			end := unpackNumber(s.inner[end_index:])
			b = StringFromSliceUnchecked(s.inner[start:end])
		}
	}
	return b
}

func (s *StringVec) AsBuilder() StringVecBuilder {
	size := s.ItemCount()
	t := NewStringVecBuilder()
	for i := uint(0); i < size; i++ {
		t.Push(*s.Get(i))
	}
	return *t
}

type ProtocolInfoMolBuilder struct {
	name             String
	support_versions StringVec
}

func (s *ProtocolInfoMolBuilder) Build() ProtocolInfoMol {
	b := new(bytes.Buffer)

	totalSize := HeaderSizeUint * (2 + 1)
	offsets := make([]uint32, 0, 2)

	offsets = append(offsets, totalSize)
	totalSize += uint32(len(s.name.AsSlice()))
	offsets = append(offsets, totalSize)
	totalSize += uint32(len(s.support_versions.AsSlice()))

	b.Write(packNumber(Number(totalSize)))

	for i := 0; i < len(offsets); i++ {
		b.Write(packNumber(Number(offsets[i])))
	}

	b.Write(s.name.AsSlice())
	b.Write(s.support_versions.AsSlice())
	return ProtocolInfoMol{inner: b.Bytes()}
}

func (s *ProtocolInfoMolBuilder) Name(v String) *ProtocolInfoMolBuilder {
	s.name = v
	return s
}

func (s *ProtocolInfoMolBuilder) SupportVersions(v StringVec) *ProtocolInfoMolBuilder {
	s.support_versions = v
	return s
}

func NewProtocolInfoMolBuilder() *ProtocolInfoMolBuilder {
	return &ProtocolInfoMolBuilder{name: StringDefault(), support_versions: StringVecDefault()}
}

type ProtocolInfoMol struct {
	inner []byte
}

func ProtocolInfoMolFromSliceUnchecked(slice []byte) *ProtocolInfoMol {
	return &ProtocolInfoMol{inner: slice}
}
func (s *ProtocolInfoMol) AsSlice() []byte {
	return s.inner
}

func ProtocolInfoMolDefault() ProtocolInfoMol {
	return *ProtocolInfoMolFromSliceUnchecked([]byte{20, 0, 0, 0, 12, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0})
}

func ProtocolInfoMolFromSlice(slice []byte, compatible bool) (*ProtocolInfoMol, error) {
	sliceLen := len(slice)
	if uint32(sliceLen) < HeaderSizeUint {
		errMsg := strings.Join([]string{"HeaderIsBroken", "ProtocolInfoMol", strconv.Itoa(int(sliceLen)), "<", strconv.Itoa(int(HeaderSizeUint))}, " ")
		return nil, errors.New(errMsg)
	}

	totalSize := unpackNumber(slice)
	if Number(sliceLen) != totalSize {
		errMsg := strings.Join([]string{"TotalSizeNotMatch", "ProtocolInfoMol", strconv.Itoa(int(sliceLen)), "!=", strconv.Itoa(int(totalSize))}, " ")
		return nil, errors.New(errMsg)
	}

	if uint32(sliceLen) == HeaderSizeUint && 2 == 0 {
		return &ProtocolInfoMol{inner: slice}, nil
	}

	if uint32(sliceLen) < HeaderSizeUint*2 {
		errMsg := strings.Join([]string{"TotalSizeNotMatch", "ProtocolInfoMol", strconv.Itoa(int(sliceLen)), "<", strconv.Itoa(int(HeaderSizeUint * 2))}, " ")
		return nil, errors.New(errMsg)
	}

	offsetFirst := unpackNumber(slice[HeaderSizeUint:])
	if uint32(offsetFirst)%HeaderSizeUint != 0 || uint32(offsetFirst) < HeaderSizeUint*2 {
		errMsg := strings.Join([]string{"OffsetsNotMatch", "ProtocolInfoMol", strconv.Itoa(int(offsetFirst % 4)), "!= 0", strconv.Itoa(int(offsetFirst)), "<", strconv.Itoa(int(HeaderSizeUint * 2))}, " ")
		return nil, errors.New(errMsg)
	}

	if sliceLen < int(offsetFirst) {
		errMsg := strings.Join([]string{"HeaderIsBroken", "ProtocolInfoMol", strconv.Itoa(int(sliceLen)), "<", strconv.Itoa(int(offsetFirst))}, " ")
		return nil, errors.New(errMsg)
	}

	fieldCount := uint32(offsetFirst)/HeaderSizeUint - 1
	if fieldCount < 2 {
		return nil, errors.New("FieldCountNotMatch")
	} else if !compatible && fieldCount > 2 {
		return nil, errors.New("FieldCountNotMatch")
	}

	offsets := make([]uint32, fieldCount)

	for i := 0; i < int(fieldCount); i++ {
		offsets[i] = uint32(unpackNumber(slice[HeaderSizeUint:][int(HeaderSizeUint)*i:]))
	}
	offsets = append(offsets, uint32(totalSize))

	for i := 0; i < len(offsets); i++ {
		if i&1 != 0 && offsets[i-1] > offsets[i] {
			return nil, errors.New("OffsetsNotMatch")
		}
	}

	var err error

	_, err = StringFromSlice(slice[offsets[0]:offsets[1]], compatible)
	if err != nil {
		return nil, err
	}

	_, err = StringVecFromSlice(slice[offsets[1]:offsets[2]], compatible)
	if err != nil {
		return nil, err
	}

	return &ProtocolInfoMol{inner: slice}, nil
}

func (s *ProtocolInfoMol) TotalSize() uint {
	return uint(unpackNumber(s.inner))
}
func (s *ProtocolInfoMol) FieldCount() uint {
	var number uint = 0
	if uint32(s.TotalSize()) == HeaderSizeUint {
		return number
	}
	number = uint(unpackNumber(s.inner[HeaderSizeUint:]))/4 - 1
	return number
}
func (s *ProtocolInfoMol) Len() uint {
	return s.FieldCount()
}
func (s *ProtocolInfoMol) IsEmpty() bool {
	return s.Len() == 0
}
func (s *ProtocolInfoMol) CountExtraFields() uint {
	return s.FieldCount() - 2
}

func (s *ProtocolInfoMol) HasExtraFields() bool {
	return 2 != s.FieldCount()
}

func (s *ProtocolInfoMol) Name() *String {
	start := unpackNumber(s.inner[4:])
	end := unpackNumber(s.inner[8:])
	return StringFromSliceUnchecked(s.inner[start:end])
}

func (s *ProtocolInfoMol) SupportVersions() *StringVec {
	var ret *StringVec
	start := unpackNumber(s.inner[8:])
	if s.HasExtraFields() {
		end := unpackNumber(s.inner[12:])
		ret = StringVecFromSliceUnchecked(s.inner[start:end])
	} else {
		ret = StringVecFromSliceUnchecked(s.inner[start:])
	}
	return ret
}

func (s *ProtocolInfoMol) AsBuilder() ProtocolInfoMolBuilder {
	ret := NewProtocolInfoMolBuilder().Name(*s.Name()).SupportVersions(*s.SupportVersions())
	return *ret
}
