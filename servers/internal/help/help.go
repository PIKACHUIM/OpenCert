// Package help 提供平台帮助中心文档（随二进制嵌入，版本与代码一致）。
//
// 文档分两类受众：
//   - user：面向所有访客与用户（门户与控制台均可见）
//   - admin：面向平台管理员（仅登录管理员可通过 adminOnly 接口获取）
//
// 文档格式为 Markdown，文件头使用简单 front matter：
//
//	---
//	title: 标题
//	summary: 一句话摘要
//	order: 10
//	---
package help

import (
	"embed"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

//go:embed docs/user/*.md docs/admin/*.md
var docsFS embed.FS

// Audience 是文档受众。
type Audience string

const (
	AudienceUser  Audience = "user"
	AudienceAdmin Audience = "admin"
)

// Doc 是一篇帮助文档。
type Doc struct {
	Slug     string   `json:"slug"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Audience Audience `json:"audience"`
	Order    int      `json:"order"`
	Content  string   `json:"content"`
}

// List 返回指定受众的全部文档（按 order、slug 排序）。
func List(aud Audience) ([]Doc, error) {
	dir := "docs/" + string(aud)
	entries, err := fs.ReadDir(docsFS, dir)
	if err != nil {
		return nil, err
	}
	docs := make([]Doc, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		raw, err := docsFS.ReadFile(path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		d := parse(string(raw))
		d.Slug = strings.TrimSuffix(e.Name(), ".md")
		d.Audience = aud
		docs = append(docs, d)
	}
	sort.SliceStable(docs, func(i, j int) bool {
		if docs[i].Order != docs[j].Order {
			return docs[i].Order < docs[j].Order
		}
		return docs[i].Slug < docs[j].Slug
	})
	return docs, nil
}

// parse 解析 front matter 与正文。
func parse(raw string) Doc {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	d := Doc{Content: raw}
	if !strings.HasPrefix(raw, "---\n") {
		return d
	}
	end := strings.Index(raw[4:], "\n---\n")
	if end < 0 {
		return d
	}
	header := raw[4 : 4+end]
	d.Content = strings.TrimLeft(raw[4+end+5:], "\n")
	for _, line := range strings.Split(header, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "title":
			d.Title = v
		case "summary":
			d.Summary = v
		case "order":
			d.Order, _ = strconv.Atoi(v)
		}
	}
	return d
}
