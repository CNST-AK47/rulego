/*
 * Copyright 2023 The RuleGo Authors.
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

// Package endpoint /**

package endpoint

import (
	"context"
	"fmt"
	"github.com/rulego/rulego"
	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/utils/str"
	"net/textproto"
	"strings"
	"sync"
)

const (
	pathKey = "_path"
)

//Message 接收端点数据抽象接口
//不同输入源数据统一接口
type Message interface {
	//Body message body
	Body() []byte
	Headers() textproto.MIMEHeader
	From() string
	//GetParam http.Request#FormValue
	GetParam(key string) string
	//SetMsg set RuleMsg
	SetMsg(msg *types.RuleMsg)
	//GetMsg 把接收数据转换成 RuleMsg
	GetMsg() *types.RuleMsg
	//SetStatusCode 响应 code
	SetStatusCode(statusCode int)
	//SetBody 响应 body
	SetBody(body []byte)
}

//Exchange 包含in 和out message
type Exchange struct {
	//入数据
	In Message
	//出数据
	Out Message
}

//Process 处理函数
//true:执行下一个处理器，否则不执行
type Process func(exchange *Exchange) bool

//From from端
type From struct {
	router *Router
	//来源路径
	from string
	//消息处理拦截器
	processList []Process
	//流转目标路径，例如"chain:{chainId}"，则是交给规则引擎处理数据
	to *To
}

func (f *From) ToString() string {
	return f.from
}

func (f *From) From(from string) *From {
	f.from = from
	return f
}

//Transform from端转换msg
func (f *From) Transform(transform Process) *From {
	f.processList = append(f.processList, transform)
	return f
}

//Process from端处理msg
func (f *From) Process(process Process) *From {
	f.processList = append(f.processList, process)
	return f
}

//GetProcessList 获取from端处理器列表
func (f *From) GetProcessList() []Process {
	return f.processList
}

//ExecuteProcess 执行处理函数
//true:执行To端逻辑，否则不执行
func (f *From) ExecuteProcess(exchange *Exchange) bool {
	result := true
	for _, process := range f.GetProcessList() {
		if !process(exchange) {
			result = false
			break
		}
	}
	return result
}

//To To端
//参数是组件路径，格式{executorType}:{path} executorType：执行器组件类型，path:组件路径
//如：chain:{chainId} 执行rulego中注册的规则链
//component:{nodeType} 执行在config.ComponentsRegistry 中注册的组件
//可在DefaultExecutorFactory中注册自定义执行器组件类型
//componentConfigs 组件配置参数
func (f *From) To(to string, componentConfigs ...types.Configuration) *To {
	var componentConfig = make(types.Configuration)
	for _, item := range componentConfigs {
		for k, v := range item {
			componentConfig[k] = v
		}
	}
	f.to = &To{router: f.router, to: to, componentConfig: componentConfig}
	//路径中是否有变量，如：chain:${userId}
	if strings.Contains(to, "${") && strings.Contains(to, "}") {
		f.to.HasVars = true
	}
	//获取To执行器类型
	executorType := strings.Split(to, ":")[0]

	//获取To执行器
	if executor, ok := DefaultExecutorFactory.New(executorType); ok {
		if f.to.HasVars && !executor.IsPathSupportVar() {
			panic(fmt.Errorf("executor=%s, path not support variables", executorType))
		}
		f.to.toPath = strings.TrimSpace(to[len(executorType)+1:])
		componentConfig[pathKey] = f.to.toPath
		//初始化组件
		err := executor.Init(f.router.config, componentConfig)
		if err != nil {
			panic(err)
		}
		f.to.executor = executor
	} else {
		f.to.executor = &ChainExecutor{}
		f.to.toPath = to
	}
	return f.to
}

func (f *From) GetTo() *To {
	return f.to
}

//ToComponent to组件
//参数是types.Node类型组件
func (f *From) ToComponent(node types.Node) *To {
	component := &ComponentExecutor{component: node, config: f.router.config}
	f.to = &To{router: f.router, to: node.Type(), toPath: node.Type()}
	f.to.executor = component
	return f.to
}

//End 结束返回*Router
func (f *From) End() *Router {
	return f.router
}

//To to端
type To struct {
	router *Router
	//流转目标路径，例如"chain:{chainId}"，则是交给规则引擎处理数据
	to string
	//去掉to执行器标记的路径
	toPath string
	//消息处理拦截器
	processList []Process
	//是否有占位符变量
	HasVars bool
	//componentConfig Executor组件配置
	componentConfig types.Configuration
	//目标处理器，默认是规则链处理
	executor Executor
}

//ToStringByDict 转换路径中的变量，并返回最终字符串
func (t *To) ToStringByDict(dict map[string]string) string {
	if t.HasVars {
		return str.SprintfDict(t.toPath, dict)
	}
	return t.toPath
}

func (t *To) ToString() string {
	return t.toPath
}

//Execute 执行To端逻辑
func (t *To) Execute(ctx context.Context, exchange *Exchange) {
	if t.executor != nil {
		t.executor.Execute(ctx, t.router, exchange)
	}
}

//Transform 执行To端逻辑 后转换
func (t *To) Transform(transform Process) *To {
	t.processList = append(t.processList, transform)
	return t
}

//Process 执行To端逻辑 后处理
func (t *To) Process(process Process) *To {
	t.processList = append(t.processList, process)
	return t
}

//GetProcessList 获取执行To端逻辑 处理器
func (t *To) GetProcessList() []Process {
	return t.processList
}

//End 结束返回*Router
func (t *To) End() *Router {
	return t.router
}

//Router 路由，抽象不同输入源数据路由
//把消息从输入端（From），经过转换（Transform）成RuleMsg结构，或者处理Process，然后交给规则链处理（To）
//或者 把消息从输入端（From），经过转换（Transform），然后处理响应（Process）
//用法：
//http endpoint
// endpoint.NewRouter().From("/api/v1/msg/").Transform().To("chain:xx")
// endpoint.NewRouter().From("/api/v1/msg/").Transform().Process().To("chain:xx")
// endpoint.NewRouter().From("/api/v1/msg/").Transform().Process().To("component:nodeType")
// endpoint.NewRouter().From("/api/v1/msg/").Transform().Process()
//mqtt endpoint
// endpoint.NewRouter().From("#").Transform().Process().To("chain:xx")
// endpoint.NewRouter().From("topic").Transform().Process().To("chain:xx")
type Router struct {
	//输入
	from *From
	//规则链池，默认使用rulego.DefaultRuleGo
	ruleGo *rulego.RuleGo
	config types.Config
}

//RouterOption 选项函数
type RouterOption func(*Router) error

//WithRuleGo 更改规则链池，默认使用rulego.DefaultRuleGo
func WithRuleGo(ruleGo *rulego.RuleGo) RouterOption {
	return func(re *Router) error {
		re.ruleGo = ruleGo
		return nil
	}
}

//WithRuleConfig 更改规则引擎配置
func WithRuleConfig(config types.Config) RouterOption {
	return func(re *Router) error {
		re.config = config
		return nil
	}
}

//NewRouter 创建新的路由
func NewRouter(opts ...RouterOption) *Router {
	router := &Router{ruleGo: rulego.DefaultRuleGo, config: rulego.NewConfig()}
	// 设置选项值
	for _, opt := range opts {
		_ = opt(router)
	}
	return router
}

func (r *Router) FromToString() string {
	if r.from == nil {
		return ""
	} else {
		return r.from.ToString()
	}
}

func (r *Router) From(from string) *From {
	r.from = &From{router: r, from: from}
	return r.from
}

func (r *Router) GetFrom() *From {
	return r.from
}

//BaseEndpoint 基础端点
//实现全局拦截器基础方法
type BaseEndpoint struct {
	//全局拦截器
	interceptors []Process
}

//AddInterceptors 添加全局拦截器
func (e *BaseEndpoint) AddInterceptors(interceptors ...Process) {
	e.interceptors = append(e.interceptors, interceptors...)
}

func (e *BaseEndpoint) DoProcess(router *Router, exchange *Exchange) {
	for _, item := range e.interceptors {
		//执行全局拦截器
		if !item(exchange) {
			return
		}
	}
	//执行from端逻辑
	if fromFlow := router.GetFrom(); fromFlow != nil {
		if !fromFlow.ExecuteProcess(exchange) {
			return
		}
	}
	//执行to端逻辑
	if router.GetFrom() != nil && router.GetFrom().GetTo() != nil {
		router.GetFrom().GetTo().Execute(context.TODO(), exchange)
	}
}

//Executor to端执行器
type Executor interface {
	//New 创建新的实例
	New() Executor
	//IsPathSupportVar to路径是否支持${}变量方式，默认不支持
	IsPathSupportVar() bool
	//Init 初始化
	Init(config types.Config, configuration types.Configuration) error
	//Execute 执行逻辑
	Execute(ctx context.Context, router *Router, exchange *Exchange)
}

//ExecutorFactory to端执行器工厂
type ExecutorFactory struct {
	sync.RWMutex
	executors map[string]Executor
}

//Register 注册to端执行器
func (r *ExecutorFactory) Register(name string, executor Executor) {
	r.Lock()
	r.Unlock()
	if r.executors == nil {
		r.executors = make(map[string]Executor)
	}
	r.executors[name] = executor
}

//New 根据类型创建to端执行器实例
func (r *ExecutorFactory) New(name string) (Executor, bool) {
	r.RLock()
	r.RUnlock()
	h, ok := r.executors[name]
	if ok {
		return h.New(), true
	} else {
		return nil, false
	}

}

//ChainExecutor 规则链执行器
type ChainExecutor struct {
}

func (ce *ChainExecutor) New() Executor {

	return &ChainExecutor{}
}

//IsPathSupportVar to路径允许带变量
func (ce *ChainExecutor) IsPathSupportVar() bool {
	return true
}

func (ce *ChainExecutor) Init(_ types.Config, _ types.Configuration) error {
	return nil
}

func (ce *ChainExecutor) Execute(ctx context.Context, router *Router, exchange *Exchange) {
	fromFlow := router.GetFrom()
	if fromFlow == nil {
		return
	}
	inMsg := exchange.In.GetMsg()
	if toFlow := fromFlow.GetTo(); toFlow != nil && inMsg != nil {
		toChainId := toFlow.ToStringByDict(inMsg.Metadata.Values())

		//查找规则链，并执行
		if ruleEngine, ok := router.ruleGo.Get(toChainId); ok {
			ruleEngine.OnMsgWithOptions(*inMsg, types.WithContext(ctx),
				types.WithEndFunc(func(msg types.RuleMsg, err error) {
					exchange.Out.SetMsg(&msg)
					for _, process := range toFlow.GetProcessList() {
						if !process(exchange) {
							break
						}
					}
				}))
		}

	}
}

//ComponentExecutor node组件执行器
type ComponentExecutor struct {
	component types.Node
	config    types.Config
}

func (ce *ComponentExecutor) New() Executor {
	return &ComponentExecutor{}
}

//IsPathSupportVar to路径不允许带变量
func (ce *ComponentExecutor) IsPathSupportVar() bool {
	return false
}

func (ce *ComponentExecutor) Init(config types.Config, configuration types.Configuration) error {
	ce.config = config
	if configuration == nil {
		return fmt.Errorf("nodeType can't empty")
	}
	nodeType := configuration.GetToString(pathKey)
	node, err := config.ComponentsRegistry.NewNode(nodeType)
	if err == nil {
		ce.component = node
		err = ce.component.Init(config, configuration)
	}
	return err
}

func (ce *ComponentExecutor) Execute(ctx context.Context, router *Router, exchange *Exchange) {
	if ce.component != nil {
		fromFlow := router.GetFrom()
		if fromFlow == nil {
			return
		}

		inMsg := exchange.In.GetMsg()
		if toFlow := fromFlow.GetTo(); toFlow != nil && inMsg != nil {
			//初始化的空上下文
			ruleCtx := rulego.NewRuleContext(ce.config, nil, nil, nil, ce.config.Pool, func(msg types.RuleMsg, err error) {
				exchange.Out.SetMsg(&msg)
				for _, process := range toFlow.GetProcessList() {
					if !process(exchange) {
						break
					}
				}
			}, ctx)

			//执行组件逻辑
			_ = ce.component.OnMsg(ruleCtx, *inMsg)
		}
	}
}

//DefaultExecutorFactory 默认to端执行器注册器
var DefaultExecutorFactory = new(ExecutorFactory)

//注册默认执行器
func init() {
	DefaultExecutorFactory.Register("chain", &ChainExecutor{})
	DefaultExecutorFactory.Register("component", &ComponentExecutor{})
}