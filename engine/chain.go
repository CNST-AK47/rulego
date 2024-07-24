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
	"context"
	"fmt"
	"sync"

	"github.com/rulego/rulego/api/types"
	"github.com/rulego/rulego/utils/aes"
	"github.com/rulego/rulego/utils/str"
)

// RelationCache is a structure that caches the outgoing node relationships based on the incoming node.
type RelationCache struct {
	// inNodeId is the identifier of the incoming node.
	inNodeId types.RuleNodeId
	// relationType is the type of relationship with the outgoing node.
	relationType string
}

// RuleChainCtx defines an instance of a rule chain.
// It initializes all nodes and records the routing relationships between all nodes in the rule chain.
type RuleChainCtx struct {
	// Id is the identifier of the node.
	Id types.RuleNodeId
	// SelfDefinition is the definition of the rule chain.
	SelfDefinition *types.RuleChain
	// config is the configuration of the rule engine.
	config types.Config
	// initialized indicates whether the rule chain context has been initialized.
	initialized bool
	// componentsRegistry is the registry of components.
	componentsRegistry types.ComponentRegistry
	// nodeIds is a list of node identifiers.
	nodeIds []types.RuleNodeId
	// nodes is a map of node contexts.
	nodes map[types.RuleNodeId]types.NodeCtx
	// nodeRoutes is a map of node routing relationships.
	nodeRoutes map[types.RuleNodeId][]types.RuleNodeRelation
	// relationCache caches the outgoing node lists based on the incoming node and relationship.
	relationCache map[RelationCache][]types.NodeCtx
	// rootRuleContext is the root context of the rule chain.
	rootRuleContext types.RuleContext
	// ruleChainPool is a pool of sub-rule chains.
	ruleChainPool types.RuleEnginePool
	// aspects is a list of AOP (Aspect-Oriented Programming) aspects.
	aspects types.AspectList
	// afterReloadAspects is a list of aspects triggered on after reload.
	afterReloadAspects []types.OnReloadAspect
	// destroyAspects is a list of aspects triggered on destruction.
	destroyAspects []types.OnDestroyAspect
	// vars is a map of variables.
	vars map[string]string
	// decryptSecrets is a map of decrypted secrets.
	decryptSecrets map[string]string
	// isEmpty indicates whether the rule chain has no nodes.
	isEmpty bool
	// RWMutex is a read/write mutex lock.
	sync.RWMutex
}

// InitRuleChainCtx initializes a RuleChainCtx with the given configuration, aspects, and rule chain definition.
// 初始化规则链上下文
func InitRuleChainCtx(config types.Config, aspects types.AspectList, ruleChainDef *types.RuleChain) (*RuleChainCtx, error) {
	// Retrieve aspects for the engine.
	// 获取切面上下文
	chainBeforeInitAspects, _, _, afterReloadAspects, destroyAspects := aspects.GetEngineAspects()
	// 执行规则引擎初始化函数
	for _, aspect := range chainBeforeInitAspects {
		// 规则引擎初始化的节点--执行初始化函数
		if err := aspect.OnChainBeforeInit(ruleChainDef); err != nil {
			return nil, err
		}
	}

	// Initialize a new RuleChainCtx with the provided configuration and aspects.
	// 初始化规则链上下文
	var ruleChainCtx = &RuleChainCtx{
		config:             config,                                              // 配置信息
		SelfDefinition:     ruleChainDef,                                        // 规则链定义
		nodes:              make(map[types.RuleNodeId]types.NodeCtx),            // 规则链中节点
		nodeRoutes:         make(map[types.RuleNodeId][]types.RuleNodeRelation), // 规则链中节点关联列表
		relationCache:      make(map[RelationCache][]types.NodeCtx),             // 对应缓存
		componentsRegistry: config.ComponentsRegistry,                           // 全局组件注册器
		initialized:        true,                                                // 师傅已经初始化
		aspects:            aspects,                                             // 切面
		afterReloadAspects: afterReloadAspects,                                  // 重载后切片
		destroyAspects:     destroyAspects,                                      // 销毁切片
	}
	// Set the ID of the rule chain context if provided in the definition.
	// 设置规则链上下文ID
	if ruleChainDef.RuleChain.ID != "" {
		ruleChainCtx.Id = types.RuleNodeId{Id: ruleChainDef.RuleChain.ID, Type: types.CHAIN}
	}
	// Process the rule chain configuration's vars and secrets.
	// 进行规则链中配置上下文的处理
	if ruleChainDef != nil && ruleChainDef.RuleChain.Configuration != nil {
		// 获取定义配置
		varsConfig := ruleChainDef.RuleChain.Configuration[types.Vars]
		// 将其转变为map
		ruleChainCtx.vars = str.ToStringMapString(varsConfig)
		// 获取环境配置
		envConfig := ruleChainDef.RuleChain.Configuration[types.Secrets]
		// 加密信息
		secrets := str.ToStringMapString(envConfig)
		// 解密信息
		ruleChainCtx.decryptSecrets = decryptSecret(secrets, []byte(config.SecretKey))
	}
	// 获取节点列表
	nodeLen := len(ruleChainDef.Metadata.Nodes)
	ruleChainCtx.nodeIds = make([]types.RuleNodeId, nodeLen)
	// Load all node information.
	// 加载所有节点
	for index, item := range ruleChainDef.Metadata.Nodes {
		if item.Id == "" {
			item.Id = fmt.Sprintf(defaultNodeIdPrefix+"%d", index)
		}
		ruleNodeId := types.RuleNodeId{Id: item.Id, Type: types.NODE}
		ruleChainCtx.nodeIds[index] = ruleNodeId
		// 初始化节点上下文
		ruleNodeCtx, err := InitRuleNodeCtx(config, ruleChainCtx, aspects, item)
		if err != nil {
			return nil, err
		}
		// 更新节点上下文
		ruleChainCtx.nodes[ruleNodeId] = ruleNodeCtx
	}
	// Load node relationship information.
	// 登记节点之间的关联关系
	for _, item := range ruleChainDef.Metadata.Connections {
		inNodeId := types.RuleNodeId{Id: item.FromId, Type: types.NODE}
		outNodeId := types.RuleNodeId{Id: item.ToId, Type: types.NODE}
		// 定义节点连接关系
		ruleNodeRelation := types.RuleNodeRelation{
			InId:         inNodeId,
			OutId:        outNodeId,
			RelationType: item.Type,
		}
		// 查询节点关系
		nodeRelations, ok := ruleChainCtx.nodeRoutes[inNodeId]
		if !ok {
			nodeRelations = []types.RuleNodeRelation{}
		}
		nodeRelations = append(nodeRelations, ruleNodeRelation)
		// 更新节点路由
		ruleChainCtx.nodeRoutes[inNodeId] = nodeRelations
	}
	// Load sub-rule chains.
	// 加载子规则链关联关系
	for _, item := range ruleChainDef.Metadata.RuleChainConnections {
		inNodeId := types.RuleNodeId{Id: item.FromId, Type: types.NODE}
		outNodeId := types.RuleNodeId{Id: item.ToId, Type: types.CHAIN}
		ruleChainRelation := types.RuleNodeRelation{
			InId:         inNodeId,
			OutId:        outNodeId,
			RelationType: item.Type,
		}
		// 查询子规则接入节点
		nodeRelations, ok := ruleChainCtx.nodeRoutes[inNodeId]
		if ok {
			nodeRelations = append(nodeRelations, ruleChainRelation)
		} else {
			nodeRelations = []types.RuleNodeRelation{ruleChainRelation}
		}
		// 更新关系
		ruleChainCtx.nodeRoutes[inNodeId] = nodeRelations
	}
	// Initialize the root rule context.
	// 初始化根节点上下文
	if firstNode, ok := ruleChainCtx.GetFirstNode(); ok {
		// 获取根节点上下文
		ruleChainCtx.rootRuleContext = NewRuleContext(context.TODO(), ruleChainCtx.config, ruleChainCtx, nil,
			firstNode, config.Pool, nil, nil)
	} else {
		// If there are no nodes, initialize an empty node context.
		// 初始化一个空节点上下文
		ruleNodeCtx, _ := InitRuleNodeCtx(config, ruleChainCtx, aspects, &types.RuleNode{})
		ruleChainCtx.rootRuleContext = NewRuleContext(context.TODO(), ruleChainCtx.config, ruleChainCtx, nil,
			ruleNodeCtx, config.Pool, nil, nil)
		ruleChainCtx.isEmpty = true
	}

	return ruleChainCtx, nil
}

func (rc *RuleChainCtx) Config() types.Config {
	return rc.config
}

func (rc *RuleChainCtx) GetNodeById(id types.RuleNodeId) (types.NodeCtx, bool) {
	rc.RLock()
	defer rc.RUnlock()
	if id.Type == types.CHAIN {
		//子规则链通过规则链池查找
		if subRuleEngine, ok := rc.GetRuleEnginePool().Get(id.Id); ok && subRuleEngine.RootRuleChainCtx() != nil {
			return subRuleEngine.RootRuleChainCtx(), true
		} else {
			return nil, false
		}
	} else {
		ruleNodeCtx, ok := rc.nodes[id]
		return ruleNodeCtx, ok
	}

}

func (rc *RuleChainCtx) GetNodeByIndex(index int) (types.NodeCtx, bool) {
	if index >= len(rc.nodeIds) {
		return &RuleNodeCtx{}, false
	}
	return rc.GetNodeById(rc.nodeIds[index])
}

// GetFirstNode 获取第一个节点，消息从该节点开始流转。默认是index=0的节点
func (rc *RuleChainCtx) GetFirstNode() (types.NodeCtx, bool) {
	var firstNodeIndex = rc.SelfDefinition.Metadata.FirstNodeIndex
	return rc.GetNodeByIndex(firstNodeIndex)
}

func (rc *RuleChainCtx) GetNodeRoutes(id types.RuleNodeId) ([]types.RuleNodeRelation, bool) {
	rc.RLock()
	defer rc.RUnlock()
	relations, ok := rc.nodeRoutes[id]
	return relations, ok
}

// GetNextNodes 获取当前节点指定关系的子节点
func (rc *RuleChainCtx) GetNextNodes(id types.RuleNodeId, relationType string) ([]types.NodeCtx, bool) {
	var nodeCtxList []types.NodeCtx
	cacheKey := RelationCache{inNodeId: id, relationType: relationType}
	rc.RLock()
	//get from cache
	nodeCtxList, ok := rc.relationCache[cacheKey]
	rc.RUnlock()
	if ok {
		return nodeCtxList, nodeCtxList != nil
	}

	//get from the Routes
	relations, ok := rc.GetNodeRoutes(id)
	hasNextComponents := false
	if ok {
		for _, item := range relations {
			if item.RelationType == relationType {
				if nodeCtx, nodeCtxOk := rc.GetNodeById(item.OutId); nodeCtxOk {
					nodeCtxList = append(nodeCtxList, nodeCtx)
					hasNextComponents = true
				}
			}
		}
	}
	rc.Lock()
	//add to the cache
	rc.relationCache[cacheKey] = nodeCtxList
	rc.Unlock()
	return nodeCtxList, hasNextComponents
}

// Type 组件类型
func (rc *RuleChainCtx) Type() string {
	return "ruleChain"
}

func (rc *RuleChainCtx) New() types.Node {
	panic("not support this func")
}

// Init 初始化
func (rc *RuleChainCtx) Init(_ types.Config, configuration types.Configuration) error {
	if rootRuleChainDef, ok := configuration["selfDefinition"]; ok {
		if v, ok := rootRuleChainDef.(*types.RuleChain); ok {
			if ruleChainCtx, err := InitRuleChainCtx(rc.config, rc.aspects, v); err == nil {
				rc.Copy(ruleChainCtx)
			} else {
				return err
			}
		}
	}
	return nil
}

// OnMsg 处理消息
func (rc *RuleChainCtx) OnMsg(ctx types.RuleContext, msg types.RuleMsg) {
	ctx.TellFlow(context.Background(), rc.Id.Id, msg, nil, nil)
}

func (rc *RuleChainCtx) Destroy() {
	rc.RLock()
	defer rc.RUnlock()
	for _, v := range rc.nodes {
		temp := v
		temp.Destroy()
	}
	//执行销毁切面逻辑
	for _, aop := range rc.destroyAspects {
		aop.OnDestroy(rc)
	}
}

func (rc *RuleChainCtx) IsDebugMode() bool {
	return rc.SelfDefinition.RuleChain.DebugMode
}

func (rc *RuleChainCtx) GetNodeId() types.RuleNodeId {
	return rc.Id
}

func (rc *RuleChainCtx) ReloadSelf(def []byte) error {
	var err error
	var ctx types.Node
	if ctx, err = rc.config.Parser.DecodeRuleChain(rc.config, rc.aspects, def); err == nil {
		rc.Destroy()
		rc.Copy(ctx.(*RuleChainCtx))
		//执行reload切面
		for _, aop := range rc.afterReloadAspects {
			if err := aop.OnReload(rc, rc); err != nil {
				return err
			}
		}
	}
	return err
}

func (rc *RuleChainCtx) ReloadChild(ruleNodeId types.RuleNodeId, def []byte) error {
	if node, ok := rc.GetNodeById(ruleNodeId); ok {
		//更新子节点
		err := node.ReloadSelf(def)
		//执行reload切面
		for _, aop := range rc.afterReloadAspects {
			if err := aop.OnReload(rc, node); err != nil {
				return err
			}
		}
		return err
	}
	return nil
}

func (rc *RuleChainCtx) DSL() []byte {
	v, _ := rc.config.Parser.EncodeRuleChain(rc.SelfDefinition)
	return v
}

func (rc *RuleChainCtx) Definition() *types.RuleChain {
	return rc.SelfDefinition
}

// Copy 复制
func (rc *RuleChainCtx) Copy(newCtx *RuleChainCtx) {
	rc.Lock()
	defer rc.Unlock()
	rc.Id = newCtx.Id
	rc.config = newCtx.config
	rc.initialized = newCtx.initialized
	rc.componentsRegistry = newCtx.componentsRegistry
	rc.SelfDefinition = newCtx.SelfDefinition
	rc.nodeIds = newCtx.nodeIds
	rc.nodes = newCtx.nodes
	rc.nodeRoutes = newCtx.nodeRoutes
	rc.rootRuleContext = newCtx.rootRuleContext
	rc.aspects = newCtx.aspects
	rc.afterReloadAspects = newCtx.afterReloadAspects
	rc.destroyAspects = newCtx.destroyAspects
	rc.vars = newCtx.vars
	rc.decryptSecrets = newCtx.decryptSecrets
	//清除缓存
	rc.relationCache = make(map[RelationCache][]types.NodeCtx)
}

// SetRuleEnginePool 设置子规则链池
func (rc *RuleChainCtx) SetRuleEnginePool(ruleChainPool types.RuleEnginePool) {
	rc.ruleChainPool = ruleChainPool
}

// GetRuleEnginePool 获取子规则链池
func (rc *RuleChainCtx) GetRuleEnginePool() types.RuleEnginePool {
	if rc.ruleChainPool == nil {
		return DefaultPool
	} else {
		return rc.ruleChainPool
	}
}

func (rc *RuleChainCtx) SetAspects(aspects types.AspectList) {
	rc.aspects = aspects
	_, _, _, afterReloadAspects, destroyAspects := aspects.GetEngineAspects()
	rc.afterReloadAspects = afterReloadAspects
	rc.destroyAspects = destroyAspects
}

func (rc *RuleChainCtx) GetAspects() types.AspectList {
	return rc.aspects
}

func decryptSecret(inputMap map[string]string, secretKey []byte) map[string]string {
	result := make(map[string]string)
	for key, value := range inputMap {
		if plaintext, err := aes.Decrypt(value, secretKey); err == nil {
			result[key] = plaintext
		} else {
			result[key] = value
		}
	}
	return result
}
