package pkcs11

import (
	"encoding/binary"
	"unsafe"
)

// layout 描述目标模块的结构体布局。
//
// PKCS#11 头文件在「是否对结构体做 1 字节打包」上没有统一约定：
//   - 绝大多数厂商模块（eToken / SoftHSM / NSS / OpenSC）使用编译器默认的自然对齐；
//   - 部分模块（含本项目仓库内 drivers 目录的模块）在包含 cryptoki 头前加了
//     `#pragma pack(push, cryptoki, 1)`，使结构体按 1 字节紧凑排列。
//
// 在 64 位平台上，两者的差异只出现在「含 4 字节 CK_ULONG + 8 字节指针」的结构体上
// （Windows）；LP64 平台上 CK_ULONG 本身是 8 字节，两种布局退化为一致。
type layout struct {
	packed    bool
	ulongSize int
	ptrSize   int

	// attrSize / mechSize 是 CK_ATTRIBUTE / CK_MECHANISM 的字节大小。
	attrSize int
	mechSize int

	// CK_ATTRIBUTE 内部字段偏移
	attrValueOff int
	attrLenOff   int

	// CK_MECHANISM 内部字段偏移
	mechParamOff int
	mechLenOff   int

	// CK_INFO 内部字段偏移与总大小
	infoFlagsOff int
	infoDescOff  int
	infoTotal    int

	// CK_SLOT_INFO / CK_TOKEN_INFO 总大小（用于分配缓冲区）
	slotInfoTotal  int
	tokenInfoTotal int
}

func newLayout(packed bool) layout {
	u := int(unsafe.Sizeof(ckULong(0)))
	p := int(unsafe.Sizeof(uintptr(0)))
	l := layout{packed: packed, ulongSize: u, ptrSize: p}

	if packed {
		l.attrSize = u + p + u
		l.attrValueOff = u
		l.attrLenOff = u + p
		l.mechSize = u + p + u
		l.mechParamOff = u
		l.mechLenOff = u + p
		l.infoFlagsOff = 2 + 32
		l.infoDescOff = l.infoFlagsOff + u
		l.infoTotal = l.infoDescOff + 32 + 2
	} else {
		l.attrSize = alignUpInt(alignUpInt(u, p)+p+u, p)
		l.attrValueOff = alignUpInt(u, p)
		l.attrLenOff = l.attrValueOff + p
		l.mechSize = l.attrSize
		l.mechParamOff = l.attrValueOff
		l.mechLenOff = l.attrLenOff
		l.infoFlagsOff = alignUpInt(2+32, u)
		l.infoDescOff = l.infoFlagsOff + u
		l.infoTotal = alignUpInt(l.infoDescOff+32+2, u)
	}

	// CK_SLOT_INFO：64 + 32 + ulong + 2 + 2（自然对齐与打包在 64 位平台上一致）
	l.slotInfoTotal = alignUpInt(96+u, u) + 4
	// CK_TOKEN_INFO：96 + ulong + 10*ulong + 2 + 2 + 16
	l.tokenInfoTotal = 96 + u + 10*u + 4 + 16
	if !packed {
		l.tokenInfoTotal = alignUpInt(l.tokenInfoTotal, u)
	}
	return l
}

func alignUpInt(v, a int) int {
	if a <= 0 || v%a == 0 {
		return v
	}
	return v + a - v%a
}

// ---- 属性模板序列化 ----

// attrBuffer 按目标布局序列化 CK_ATTRIBUTE 数组及其指向的值。
type attrBuffer struct {
	l   layout
	typ []ckULong
	val [][]byte
	raw []byte
}

func newAttrBuffer(l layout) *attrBuffer {
	return &attrBuffer{l: l}
}

func (b *attrBuffer) add(typ ckULong, val []byte) *attrBuffer {
	cp := make([]byte, len(val))
	copy(cp, val)
	b.typ = append(b.typ, typ)
	b.val = append(b.val, cp)
	return b
}

func (b *attrBuffer) addULong(typ ckULong, v ckULong) *attrBuffer {
	buf := make([]byte, b.l.ulongSize)
	if b.l.ulongSize == 4 {
		binary.LittleEndian.PutUint32(buf, uint32(v))
	} else {
		binary.LittleEndian.PutUint64(buf, uint64(v))
	}
	return b.add(typ, buf)
}

func (b *attrBuffer) addBool(typ ckULong, v bool) *attrBuffer {
	if v {
		return b.add(typ, []byte{1})
	}
	return b.add(typ, []byte{0})
}

func (b *attrBuffer) addString(typ ckULong, s string) *attrBuffer {
	return b.add(typ, []byte(s))
}

// len 返回条目数。
func (b *attrBuffer) count() ckULong { return ckULong(len(b.typ)) }

// index 返回第 i 项的类型（用于读回后校验）。
func (b *attrBuffer) index(i int) ckULong { return b.typ[i] }

// setValue 替换第 i 项的值（用于「先探测长度、再分配缓冲」的两段式读取）。
func (b *attrBuffer) setValue(i int, v []byte) {
	b.val[i] = v
}

// valueLenFromRaw 从已写入的缓冲区读回第 i 项的 ulValueLen。
func (b *attrBuffer) valueLenFromRaw(i int) ckULong {
	off := i*b.l.attrSize + b.l.attrLenOff
	return b.l.readULong(b.raw[off:])
}

// writeValueLen 在缓冲区中写回第 i 项的 ulValueLen（部分实现只更新长度）。
func (b *attrBuffer) writeValueLen(i int, n ckULong) {
	off := i*b.l.attrSize + b.l.attrLenOff
	b.l.writeULong(b.raw[off:], n)
}

// serialize 生成 CK_ATTRIBUTE 数组内存；返回的指针需配合 runtime.KeepAlive(b) 使用。
func (b *attrBuffer) serialize() (unsafe.Pointer, ckULong) {
	n := len(b.typ)
	b.raw = make([]byte, n*b.l.attrSize)
	for i := 0; i < n; i++ {
		base := i * b.l.attrSize
		b.l.writeULong(b.raw[base:], b.typ[i])
		if len(b.val[i]) > 0 {
			p := uintptr(unsafe.Pointer(&b.val[i][0]))
			b.l.writePtr(b.raw[base+b.l.attrValueOff:], p)
			b.l.writeULong(b.raw[base+b.l.attrLenOff:], ckULong(len(b.val[i])))
		}
	}
	if n == 0 {
		return nil, 0
	}
	return unsafe.Pointer(&b.raw[0]), ckULong(n)
}

// ---- 机制序列化 ----

// mechBuffer 按目标布局序列化 CK_MECHANISM。
type mechBuffer struct {
	l     layout
	raw   []byte
	param []byte // 机制参数内存（保持存活）
}

func newMechBuffer(l layout, mech ckULong, param []byte) *mechBuffer {
	b := &mechBuffer{l: l, param: param}
	b.raw = make([]byte, l.mechSize)
	l.writeULong(b.raw, mech)
	if len(param) > 0 {
		l.writePtr(b.raw[l.mechParamOff:], uintptr(unsafe.Pointer(&param[0])))
		l.writeULong(b.raw[l.mechLenOff:], ckULong(len(param)))
	}
	return b
}

// ptr 返回 CK_MECHANISM 指针（需 runtime.KeepAlive(mechBuffer)）。
func (b *mechBuffer) ptr() unsafe.Pointer { return unsafe.Pointer(&b.raw[0]) }

// mechanism 返回机制常量（测试与排障用）。
func (b *mechBuffer) mechanism() ckULong { return b.l.readULong(b.raw) }

// paramBytes 返回机制参数字节（测试与排障用）。
func (b *mechBuffer) paramBytes() []byte { return b.param }

// oaepParams 按布局序列化 CK_RSA_PKCS_OAEP_PARAMS（pSourceData 固定为 NULL）。
func (l layout) oaepParams(hashAlg, mgf, source ckULong) []byte {
	buf := make([]byte, l.paramStructSize(3))
	l.writeULong(buf[0:], hashAlg)
	l.writeULong(buf[l.ulongSize:], mgf)
	l.writeULong(buf[2*l.ulongSize:], source)
	return buf
}

// pssParams 按布局序列化 CK_RSA_PKCS_PSS_PARAMS。
func (l layout) pssParams(hashAlg, mgf, saltLen ckULong) []byte {
	buf := make([]byte, l.paramStructSize(3))
	l.writeULong(buf[0:], hashAlg)
	l.writeULong(buf[l.ulongSize:], mgf)
	l.writeULong(buf[2*l.ulongSize:], saltLen)
	return buf
}

// paramStructSize 计算「n 个 CK_ULONG + 1 个指针 + 1 个 CK_ULONG」结构的字节数。
func (l layout) paramStructSize(fields int) int {
	if l.packed {
		return fields*l.ulongSize + l.ptrSize + l.ulongSize
	}
	off := alignUpInt(fields*l.ulongSize, l.ptrSize) + l.ptrSize
	return alignUpInt(off+l.ulongSize, l.ptrSize)
}

// ---- 基础读写 ----

func (l layout) writeULong(dst []byte, v ckULong) {
	if l.ulongSize == 4 {
		binary.LittleEndian.PutUint32(dst[:4], uint32(v))
		return
	}
	binary.LittleEndian.PutUint64(dst[:8], uint64(v))
}

func (l layout) readULong(src []byte) ckULong {
	if l.ulongSize == 4 {
		if len(src) < 4 {
			return 0
		}
		return ckULong(binary.LittleEndian.Uint32(src[:4]))
	}
	if len(src) < 8 {
		return 0
	}
	return ckULong(binary.LittleEndian.Uint64(src[:8]))
}

func (l layout) writePtr(dst []byte, p uintptr) {
	if l.ptrSize == 4 {
		binary.LittleEndian.PutUint32(dst[:4], uint32(p))
		return
	}
	binary.LittleEndian.PutUint64(dst[:8], uint64(p))
}

// tokenULongOffset 返回 CK_TOKEN_INFO 中第 i 个 CK_ULONG 字段的偏移（0=MaxSessionCount）。
// CK_TOKEN_INFO：Label[32]+ManufacturerID[32]+Model[16]+SerialNumber[16]=96，随后是 Flags 与 10 个 CK_ULONG。
func (l layout) tokenULongOffset(i int) int {
	return 96 + (i+1)*l.ulongSize
}

// ulongMax 返回 CK_ULONG 的「无效长度」哨兵值（PKCS#11 用 -1 表示不可读）。
func (l layout) ulongMax() ckULong {
	var max64 uint64 = 1<<64 - 1
	if l.ulongSize == 4 {
		return ckULong(1<<32 - 1)
	}
	return ckULong(max64)
}
