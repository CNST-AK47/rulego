/*
 * Copyright 2024 The RuleGo Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package str

type Template interface {
	Parse() error
	Execute(data map[string]any) string
	ExecuteFn(loadDataFunc func() map[string]any) string
	// IsNotVar 是否是模板变量，否则是普通字符串
	IsNotVar() bool
}

func NewTemplate(tmpl string, params ...any) Template {
	if CheckHasVar(tmpl) {
		return &VarTemplate{Tmpl: tmpl}
	}
	return &NotTemplate{Tmpl: tmpl}
}

// VarTemplate 模板变量支持 这种方式 ${xx}
type VarTemplate struct {
	Tmpl string
}

func (t *VarTemplate) Parse() error {
	return nil
}

func (t *VarTemplate) Execute(data map[string]any) string {
	return ExecuteTemplate(t.Tmpl, data)
}

func (t *VarTemplate) ExecuteFn(loadDataFunc func() map[string]any) string {
	var data map[string]any
	if loadDataFunc != nil {
		data = loadDataFunc()
	}
	return ExecuteTemplate(t.Tmpl, data)
}

func (t *VarTemplate) IsNotVar() bool {
	return false
}

// NotTemplate 原样输出
type NotTemplate struct {
	Tmpl string
}

func (t *NotTemplate) Parse() error {
	return nil
}

func (t *NotTemplate) Execute(data map[string]any) string {
	return t.Tmpl
}

func (t *NotTemplate) ExecuteFn(loadDataFunc func() map[string]any) string {
	return t.Tmpl
}

func (t *NotTemplate) IsNotVar() bool {
	return true
}
