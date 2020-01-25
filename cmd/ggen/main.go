package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type apiGenCnfg struct {
	Entity       string
	Item         string
	Configurable bool
	IsCollection bool
	Modificators []string
	Helpers      []string
}

func main() {
	ent := flag.String("ent", "", "Entity struct name")
	item := flag.String("item", "", "Child entity struct name")
	conf := flag.Bool("conf", false, "Has Conf() method")
	coll := flag.Bool("coll", false, "Is collection entity")
	mods := flag.String("mods", "", "Modifiers comma separated list")
	helpers := flag.String("helpers", "", "Helpers comma separated list")
	flag.Parse()

	if *ent == "" {
		fmt.Printf("can't generate %+v as no entity is provided, skipping...\n", os.Args)
		return
	}

	m := []string{}
	if len(*mods) > 0 {
		m = strings.Split(*mods, ",")
	}

	h := []string{}
	if len(*helpers) > 0 {
		h = strings.Split(*helpers, ",")
	}

	generate(&apiGenCnfg{
		Entity:       *ent,
		Item:         *item,
		Configurable: *conf,
		IsCollection: *coll,
		Modificators: m,
		Helpers:      h,
	})
}

func generate(c *apiGenCnfg) error {
	pkgPath, _ := filepath.Abs("./")
	pkg := filepath.Base(pkgPath)

	instance := instanceOf(c.Entity)
	genFileName := fmt.Sprintf("%s_gen.go", instance)

	code := fmt.Sprintf("// Package api :: This is auto generated file, do not edit manually\n")
	code += fmt.Sprintf("package %s\n", pkg)

	if !c.IsCollection && len(c.Helpers) > 0 {
		for _, helper := range c.Helpers {
			if helper == "Data" {
				code += `
					import "encoding/json"
				`
			}
		}
	}

	if c.Configurable {
		code += `
			// Conf receives custom request config definition, e.g. custom headers, custom OData mod
			func (` + instance + ` *` + c.Entity + `) Conf(config *RequestConfig) *` + c.Entity + ` {
				` + instance + `.config = config
				return ` + instance + `
			}
		`
	}

	if len(c.Modificators) > 0 {
		code += modificatorsGen(c)
	}

	if len(c.Helpers) > 0 {
		code += helpersGen(c)
	}

	err := ioutil.WriteFile(filepath.Join("./", genFileName), []byte(code), 0644)
	return err
}

func modificatorsGen(c *apiGenCnfg) string {
	Ent := c.Entity
	ent := instanceOf(c.Entity)
	code := ""
	for _, mod := range c.Modificators {
		switch mod {
		case "Select":
			code += `
				// Select adds $select OData modifier
				func (` + ent + ` *` + Ent + `) Select(oDataSelect string) *` + Ent + ` {
					` + ent + `.modifiers.AddSelect(oDataSelect)
					return ` + ent + `
				}
			`
		case "Expand":
			code += `
				// Expand adds $expand OData modifier
				func (` + ent + ` *` + Ent + `) Expand(oDataExpand string) *` + Ent + ` {
					` + ent + `.modifiers.AddExpand(oDataExpand)
					return ` + ent + `
				}
			`
		case "Filter":
			code += `
				// Filter adds $filter OData modifier
				func (` + ent + ` *` + Ent + `) Filter(oDataFilter string) *` + Ent + ` {
					` + ent + `.modifiers.AddFilter(oDataFilter)
					return ` + ent + `
				}
			`
		case "Top":
			code += `
				// Top adds $top OData modifier
				func (` + ent + ` *` + Ent + `) Top(oDataTop int) *` + Ent + ` {
					` + ent + `.modifiers.AddTop(oDataTop)
					return ` + ent + `
				}
			`
		case "Skip":
			code += `
				// Skip adds $skiptoken OData modifier
				func (` + ent + ` *` + Ent + `) Skip(skipToken string) *` + Ent + ` {
					` + ent + `.modifiers.AddSkip(skipToken)
					return ` + ent + `
				}
			`
		case "OrderBy":
			code += `
				// OrderBy adds $orderby OData modifier
				func (` + ent + ` *` + Ent + `) OrderBy(oDataOrderBy string, ascending bool) *` + Ent + ` {
					` + ent + `.modifiers.AddOrderBy(oDataOrderBy, ascending)
					return ` + ent + `
				}
			`
		}
	}
	return code
}

func helpersGen(c *apiGenCnfg) string {
	Ent := c.Entity
	ent := instanceOf(c.Entity)
	code := ""
	if c.IsCollection && c.Item == "" {
		return ""
	}
	if len(c.Helpers) > 0 {
		code += fmt.Sprintf("\n/* Response helpers */\n")
	}
	if c.IsCollection {
		for _, mod := range c.Helpers {
			switch mod {
			case "Data":
				code += `
					// Data response helper
					func (` + ent + `Resp *` + Ent + `Resp) Data() []` + c.Item + `Resp {
						collection, _ := normalizeODataCollection(*` + ent + `Resp)
						` + ent + ` := []` + c.Item + `Resp{}
						for _, item := range collection {
							` + ent + ` = append(` + ent + `, ` + c.Item + `Resp(item))
						}
						return ` + ent + `
					}
				`
			case "Normalized":
				code += `
					// Normalized returns normalized body
					func (` + ent + `Resp *` + Ent + `Resp) Normalized() []byte {
						normalized, _ := NormalizeODataCollection(*` + ent + `Resp)
						return normalized
					}
				`
			}
		}
	}
	if !c.IsCollection {
		for _, mod := range c.Helpers {
			switch mod {
			case "Data":
				code += `
					// Data response helper
					func (` + ent + `Resp *` + Ent + `Resp) Data() *` + Ent + `Info {
						data := NormalizeODataItem(*` + ent + `Resp)
						res := &` + Ent + `Info{}
						json.Unmarshal(data, &res)
						return res
					}
				`
			case "Normalized":
				code += `
					// Normalized returns normalized body
					func (` + ent + `Resp *` + Ent + `Resp) Normalized() []byte {
						return NormalizeODataItem(*` + ent + `Resp)
					}
				`
			}
		}
	}
	return code
}

func instanceOf(entity string) string {
	if len(entity) < 4 {
		return strings.ToLower(entity)
	}
	ent := ""
	for i, l := range entity {
		pos := string(l)
		if i == 0 {
			pos = strings.ToLower(pos)
		}
		ent += pos
	}
	return ent
}
