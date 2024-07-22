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

// Package pool
// Note: This file is inspired by:
// Valyala, A. (2023) workerpool.go (Version 1.48.0)
// [Source code]. https://github.com/valyala/fasthttp/blob/master/workerpool.go
// 1.Change the Serve(c net.Conn) method to Submit(fn func()) error method
package pool

import (
	"errors"
	"runtime"
	"sync"
	"time"
)

// WorkerPool serves incoming functions using a pool of workers
// in FILO order, i.e. the most recently stopped worker will serve the next incoming function.
//
// Such a scheme keeps CPU caches hot (in theory).
// CPU线程工作池，用于快速进行工作调度
type WorkerPool struct {
	MaxWorkersCount int // 最大的线程数量

	MaxIdleWorkerDuration time.Duration // 最大超时时间

	lock         sync.Mutex // 对应的操作锁
	workersCount int        // 当前的线程数量
	mustStop     bool       // 是否必须停止

	ready []*workerChan // 已经就绪的队列列表--空闲可用的管道列表

	stopCh chan struct{} // 关停消息渠道

	workerChanPool sync.Pool // 工作线程管道池
	startOnce      sync.Once // 单例初始化锁
}

type workerChan struct {
	lastUseTime time.Time   // 上次使用时间
	ch          chan func() // 管道信息
}

// 开启工作池
func (wp *WorkerPool) Start() {
	if wp.stopCh != nil {
		return
	}
	// 进行核心初始化
	wp.startOnce.Do(func() {
		// 检查停止管道
		wp.stopCh = make(chan struct{})
		// 停止信号
		stopCh := wp.stopCh
		// 指定新的创建函数切片
		wp.workerChanPool.New = func() interface{} {
			return &workerChan{
				ch: make(chan func(), workerChanCap),
			}
		}
		// 开启子线程进行信号清理
		go func() {
			var scratch []*workerChan
			for {
				wp.clean(&scratch)
				select {
				case <-stopCh:
					return
				default:
					time.Sleep(wp.getMaxIdleWorkerDuration())
				}
			}
		}()
	})
}

func (wp *WorkerPool) Stop() {
	if wp.stopCh == nil {
		return
	}
	// 关闭对应管道
	close(wp.stopCh)
	// 重置指针
	wp.stopCh = nil

	// Stop all the workers waiting for incoming connections.
	// Do not wait for busy workers - they will stop after
	// serving the connection and noticing wp.mustStop = true.
	wp.lock.Lock()
	ready := wp.ready
	// 发送结束通知
	for i := range ready {
		ready[i].ch <- nil
		ready[i] = nil
	}
	//
	wp.ready = ready[:0]
	wp.mustStop = true
	wp.lock.Unlock()
}
func (wp *WorkerPool) Release() {
	wp.Stop()
}

// 查询最大工作时长
// 默认为10秒
func (wp *WorkerPool) getMaxIdleWorkerDuration() time.Duration {
	if wp.MaxIdleWorkerDuration <= 0 {
		return 10 * time.Second
	}
	return wp.MaxIdleWorkerDuration
}

// 清除管道列表
func (wp *WorkerPool) clean(scratch *[]*workerChan) {
	// 获取最大超时时间
	maxIdleWorkerDuration := wp.getMaxIdleWorkerDuration()

	// Clean least recently used workers if they didn't serve connections
	// for more than maxIdleWorkerDuration.
	criticalTime := time.Now().Add(-maxIdleWorkerDuration)

	wp.lock.Lock()
	ready := wp.ready
	n := len(ready)

	// Use binary-search algorithm to find out the index of the least recently worker which can be cleaned up.
	l, r, mid := 0, n-1, 0
	for l <= r {
		mid = (l + r) / 2
		if criticalTime.After(wp.ready[mid].lastUseTime) {
			l = mid + 1
		} else {
			r = mid - 1
		}
	}
	i := r
	if i == -1 {
		wp.lock.Unlock()
		return
	}
	// 创建需要停止的worker
	*scratch = append((*scratch)[:0], ready[:i+1]...)
	m := copy(ready, ready[i+1:])
	for i = m; i < n; i++ {
		ready[i] = nil
	}
	wp.ready = ready[:m]
	wp.lock.Unlock()

	// Notify obsolete workers to stop.
	// This notification must be outside the wp.lock, since ch.ch
	// may be blocking and may consume a lot of time if many workers
	// are located on non-local CPUs.
	tmp := *scratch
	// 进行关闭
	for i := range tmp {
		tmp[i].ch <- nil
		tmp[i] = nil
	}
}

// Submit submits a function for serving by the pool.
// 提交一个关键函数
func (wp *WorkerPool) Submit(fn func()) error {
	ch := wp.getCh()
	if ch == nil {
		return errors.New("no idle workers")
	}
	// 发送对应函数
	ch.ch <- fn
	return nil
}

var workerChanCap = func() int {
	// Use blocking workerChan if GOMAXPROCS=1.
	// This immediately switches Serve to WorkerFunc, which results
	// in higher performance (under go1.5 at least).
	if runtime.GOMAXPROCS(0) == 1 {
		return 0
	}

	// Use non-blocking workerChan if GOMAXPROCS>1,
	// since otherwise the Serve caller (Acceptor) may lag accepting
	// new connections if WorkerFunc is CPU-bound.
	return 1
}()

// 获取一个空闲的wokerChan
func (wp *WorkerPool) getCh() *workerChan {
	// 预先定义结果
	var ch *workerChan
	createWorker := false

	wp.lock.Lock()
	ready := wp.ready
	n := len(ready) - 1
	if n < 0 {
		if wp.workersCount < wp.MaxWorkersCount {
			createWorker = true
			wp.workersCount++
		}
	} else {
		// 取出最后一个元素
		ch = ready[n]
		ready[n] = nil
		wp.ready = ready[:n]
	}
	wp.lock.Unlock()

	if ch == nil {
		if !createWorker {
			return nil
		}
		// 创建一个新的工作线程
		// 先从池子里拿一个管道
		vch := wp.workerChanPool.Get()
		// 更新对应的队列管道
		ch = vch.(*workerChan)
		// 创建一个新的空闲管道
		go func() {
			wp.workerFunc(ch)
			// 将其放回线程池
			wp.workerChanPool.Put(vch)
		}()
	}
	return ch
}

// 释放函数
func (wp *WorkerPool) release(ch *workerChan) bool {
	// 获取上次使用时间
	ch.lastUseTime = time.Now()
	wp.lock.Lock()
	// 已经停止直接返回
	if wp.mustStop {
		wp.lock.Unlock()
		return false
	}
	// 检查是否就绪
	wp.ready = append(wp.ready, ch)
	// 进行解锁
	wp.lock.Unlock()
	return true
}

func (wp *WorkerPool) workerFunc(ch *workerChan) {
	var fn func()
	//var err error
	// 遍历管道
	// 进行管道执行
	for fn = range ch.ch {
		if fn == nil {
			break
		}
		// 执行函数
		fn()
		fn = nil

		if !wp.release(ch) {
			break
		}
	}

	wp.lock.Lock()
	wp.workersCount--
	wp.lock.Unlock()
}
