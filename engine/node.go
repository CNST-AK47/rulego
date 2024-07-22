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

package engine

import (
	"errors"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/utils/str"
)

const (
	defaultNodeIdPrefix = "node"
)

// RuleNodeCtx defines an instance of a node component within the rule engine.
type RuleNodeCtx struct {
	// Node is the instance of the component.
	types.Node
	// ChainCtx is the context of the rule chain configuration.
	ChainCtx *RuleChainCtx
	// SelfDefinition is the configuration of the component itself.
	SelfDefinition *types.RuleNode
	// config is the configuration of the rule engine.
	config types.Config
	// aspects is a list of AOP (Aspect-Oriented Programming) aspects.
	aspects types.AspectList
}

// InitRuleNodeCtx initializes a RuleNodeCtx with the given configuration, chain context, and self-definition.
// It attempts to create a new node based on the type defined in selfDefinition.
// 初始化节点上下文，用于节点上下文计算
func InitRuleNodeCtx(config types.Config, chainCtx *RuleChainCtx, aspects types.AspectList, selfDefinition *types.RuleNode) (*RuleNodeCtx, error) {
	// Retrieve aspects for the engine.
	// 获取节点切片
	_, nodeBeforeInitAspects, _, _, _ := aspects.GetEngineAspects()
	// Iterate over the nodeBeforeInitAspects and call OnNodeBeforeInit on each aspect.
	// 执行节点初始化切片
	for _, aspect := range nodeBeforeInitAspects {
		if err := aspect.OnNodeBeforeInit(selfDefinition); err != nil {
			return nil, err
		}
	}
	// Attempt to create a new node from the components registry using the type specified in selfDefinition.
	// 创建新节点
	node, err := config.ComponentsRegistry.NewNode(selfDefinition.Type)
	if err != nil {
		// If there is an error in creating the node, return a RuleNodeCtx with the provided context and definition.
		return &RuleNodeCtx{
			ChainCtx:       chainCtx,
			SelfDefinition: selfDefinition,
			config:         config,
			aspects:        aspects,
		}, err
	} else {
		// If selfDefinition.Configuration is nil, initialize it as an empty configuration.
		if selfDefinition.Configuration == nil {
			selfDefinition.Configuration = make(types.Configuration)
		}
		// Process variables within the configuration.
		// 处理配置变量
		configuration, err := processVariables(config, chainCtx, selfDefinition.Configuration)
		if err != nil {
			return &RuleNodeCtx{}, err
		}
		// Initialize the node with the processed configuration.
		// 使用配置初始化节点
		if err = node.Init(config, configuration); err != nil {
			return &RuleNodeCtx{}, err
		} else {
			// Return a RuleNodeCtx with the initialized node and provided context and definition.
			// 返回已经初始化好的节点上下文
			return &RuleNodeCtx{
				Node:           node,           // 节点
				ChainCtx:       chainCtx,       // 规则链上下文
				SelfDefinition: selfDefinition, // 定义内容
				config:         config,         // 配置信息
				aspects:        aspects,        // 对应切面
			}, nil
		}
	}
}

func (rn *RuleNodeCtx) Config() types.Config {
	return rn.config
}

func (rn *RuleNodeCtx) IsDebugMode() bool {
	return rn.SelfDefinition.DebugMode
}

func (rn *RuleNodeCtx) GetNodeId() types.RuleNodeId {
	return types.RuleNodeId{Id: rn.SelfDefinition.Id, Type: types.NODE}
}

func (rn *RuleNodeCtx) ReloadSelf(def []byte) error {
	if ruleNodeCtx, err := rn.config.Parser.DecodeRuleNode(rn.config, def, rn.ChainCtx); err == nil {
		//先销毁
		rn.Destroy()
		//重新加载
		rn.Copy(ruleNodeCtx.(*RuleNodeCtx))
		return nil
	} else {
		return err
	}
}

func (rn *RuleNodeCtx) ReloadChild(_ types.RuleNodeId, _ []byte) error {
	return errors.New("not support this func")
}

func (rn *RuleNodeCtx) GetNodeById(_ types.RuleNodeId) (types.NodeCtx, bool) {
	return nil, false
}

func (rn *RuleNodeCtx) DSL() []byte {
	v, _ := rn.config.Parser.EncodeRuleNode(rn.SelfDefinition)
	return v
}

// Copy 复制
func (rn *RuleNodeCtx) Copy(newCtx *RuleNodeCtx) {
	rn.Node = newCtx.Node
	rn.config = newCtx.config
	rn.aspects = newCtx.aspects

	rn.SelfDefinition.AdditionalInfo = newCtx.SelfDefinition.AdditionalInfo
	rn.SelfDefinition.Name = newCtx.SelfDefinition.Name
	rn.SelfDefinition.Type = newCtx.SelfDefinition.Type
	rn.SelfDefinition.DebugMode = newCtx.SelfDefinition.DebugMode
	rn.SelfDefinition.Configuration = newCtx.SelfDefinition.Configuration
}

// 使用全局配置替换节点占位符配置，例如：${global.propertyKey}
func processVariables(config types.Config, chainCtx *RuleChainCtx, configuration types.Configuration) (types.Configuration, error) {
	var result = make(types.Configuration)
	globalEnv := make(map[string]string)
	// 获取globalEnv变量
	if config.Properties != nil {
		globalEnv = config.Properties.Values()
	}
	// 定义环境
	var varsEnv map[string]string
	// 解码
	var decryptSecrets map[string]string
	// 链式上下文
	if chainCtx != nil {
		// 复制变量
		varsEnv = copyMap(chainCtx.vars)
		//解密Secrets
		decryptSecrets = copyMap(chainCtx.decryptSecrets)
	}
	// 配置获取，根据最终配置值进行获取
	for key, value := range configuration {
		if strV, ok := value.(string); ok {
			// 进行配置值替换
			v := str.SprintfVar(strV, types.Global+".", globalEnv)
			// 进行变量值替换
			v = str.SprintfVar(v, types.Vars+".", varsEnv)
			// 记录最终值
			result[key] = v
		} else {
			// 直接更新值
			result[key] = value
		}
	}
	// 检查环境变量是否正确
	if varsEnv != nil {
		result[types.Vars] = varsEnv
	}
	// 进行加密信息查询
	if decryptSecrets != nil {
		result[types.Secrets] = decryptSecrets
	}
	return result, nil
}

func copyMap(inputMap map[string]string) map[string]string {
	result := make(map[string]string)
	for key, value := range inputMap {
		result[key] = value
	}
	return result
}
