// Code generated by `ggen -ent List -conf -mods Select,Expand -helpers Normalized`; DO NOT EDIT.

package api

// Conf receives custom request config definition, e.g. custom headers, custom OData mod
func (list *List) Conf(config *RequestConfig) *List {
	list.config = config
	return list
}

// Select adds $select OData modifier
func (list *List) Select(oDataSelect string) *List {
	list.modifiers.AddSelect(oDataSelect)
	return list
}

// Expand adds $expand OData modifier
func (list *List) Expand(oDataExpand string) *List {
	list.modifiers.AddExpand(oDataExpand)
	return list
}

/* Response helpers */

// Normalized returns normalized body
func (listResp *ListResp) Normalized() []byte {
	return NormalizeODataItem(*listResp)
}
