package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"runtime"
)

// appIcon 返回托盘/窗口图标字节。
// Windows 的 LoadImage 只识别 ICO，其它平台使用 PNG。
func appIcon() []byte {
	img := renderIcon(32)
	if runtime.GOOS == "windows" {
		return encodeICO(img)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil
	}
	return buf.Bytes()
}

// renderIcon 生成应用图标：蓝紫渐变圆角方块 + 白色盾牌（与前端等待页视觉一致）。
// 采用 3x3 超采样以获得平滑边缘。
func renderIcon(size int) *image.RGBA {
	const samples = 3
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	fsize := float64(size)
	total := float64(samples * samples)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var sumR, sumG, sumB, sumA float64
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					fx := float64(x) + (float64(sx)+0.5)/samples
					fy := float64(y) + (float64(sy)+0.5)/samples
					r, g, b, a := iconSample(fx, fy, fsize)
					sumR += r * a
					sumG += g * a
					sumB += b * a
					sumA += a
				}
			}
			if sumA == 0 {
				continue
			}
			img.Set(x, y, color.RGBA{
				R: uint8(sumR / sumA),
				G: uint8(sumG / sumA),
				B: uint8(sumB / sumA),
				A: uint8(sumA / total * 255),
			})
		}
	}
	return img
}

// iconSample 返回单个采样点的颜色（分量 0-255，alpha 0-1）。
func iconSample(fx, fy, size float64) (float64, float64, float64, float64) {
	if !insideRoundedRect(fx, fy, size, size*0.22) {
		return 0, 0, 0, 0
	}

	// 沿左上→右下方向渐变：#1677ff → #722ed1
	t := (fx + fy) / (2 * size)
	r := lerp(0x16, 0x72, t)
	g := lerp(0x77, 0x2e, t)
	b := lerp(0xff, 0xd1, t)

	half := size / 2
	if insideShield((fx-half)/half, (fy-half)/half) {
		return 255, 255, 255, 1
	}
	return r, g, b, 1
}

// insideRoundedRect 判断点是否落在圆角矩形内。
func insideRoundedRect(x, y, size, radius float64) bool {
	if x < 0 || y < 0 || x > size || y > size {
		return false
	}
	cx := clamp(x, radius, size-radius)
	cy := clamp(y, radius, size-radius)
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= radius*radius
}

// insideShield 判断归一化坐标（[-1,1]）是否落在盾牌形状内：
// 顶部平直、两侧垂直，下部逐渐收窄成尖。
func insideShield(nx, ny float64) bool {
	const (
		top    = -0.62
		bottom = 0.72
		width  = 0.5
	)
	if ny < top || ny > bottom {
		return false
	}

	t := (ny - top) / (bottom - top)
	half := width
	if t > 0.55 {
		half = width * math.Pow((1-t)/0.45, 0.65)
	}
	return math.Abs(nx) <= half
}

func lerp(a, b uint8, t float64) float64 {
	return float64(a) + (float64(b)-float64(a))*t
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// encodeICO 把图像编码为单帧 32 位 BMP 型 ICO（Windows 通用图标格式）。
func encodeICO(img *image.RGBA) []byte {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	// BGRA 像素数据，自下而上存储
	pixels := make([]byte, 0, w*h*4)
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.RGBAAt(bounds.Min.X+x, bounds.Min.Y+y)
			pixels = append(pixels, c.B, c.G, c.R, c.A)
		}
	}

	// AND 掩码（1bpp，每行 4 字节对齐）：32 位带 alpha 时全 0 即可
	maskRow := ((w + 31) / 32) * 4
	mask := make([]byte, maskRow*h)

	imageSize := uint32(40 + len(pixels) + len(mask))

	out := make([]byte, 0, 22+int(imageSize))

	// ICONDIR
	out = putUint16(out, 0) // reserved
	out = putUint16(out, 1) // type = icon
	out = putUint16(out, 1) // count

	// ICONDIRENTRY
	out = append(out, byte(w), byte(h), 0, 0)
	out = putUint16(out, 1)  // planes
	out = putUint16(out, 32) // bit count
	out = putUint32(out, imageSize)
	out = putUint32(out, 22) // 图像数据偏移

	// BITMAPINFOHEADER
	out = putUint32(out, 40)
	out = putUint32(out, uint32(w))
	out = putUint32(out, uint32(h*2)) // 高度含 AND 掩码
	out = putUint16(out, 1)
	out = putUint16(out, 32)
	out = putUint32(out, 0) // BI_RGB
	out = putUint32(out, uint32(len(pixels)+len(mask)))
	out = putUint32(out, 0) // XPelsPerMeter
	out = putUint32(out, 0) // YPelsPerMeter
	out = putUint32(out, 0) // 调色板颜色数
	out = putUint32(out, 0) // 重要颜色数

	out = append(out, pixels...)
	out = append(out, mask...)
	return out
}

func putUint16(b []byte, v uint16) []byte {
	return binary.LittleEndian.AppendUint16(b, v)
}

func putUint32(b []byte, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(b, v)
}
