package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync/atomic"
	"time"

	"artemis/agent"
	"artemis/db"
)

// 任务级超时协调器(见 docs/任务级超时与收尾设计.md §4/§8.5)。
// 绝对墙钟:每个带 timeout 的任务一个定时 goroutine,到点驱动有序收尾时序:
//   ① settling → ② worker 停领新意图 / ③ planner 丢弃普通 notify
//   ④ 等在跑 worker drain(受 grace) → ⑤ 终局一轮 planner 判定 → ⑥ 定终态(带守卫)

const (
	settleDrainGrace     = 90 * time.Second // 等在跑 worker 优雅收尾的上限;超过则硬 cancel
	deadlinePollInterval = 2 * time.Second  // deadline 未盖章/LLM 未就绪时的轮询间隔
	deadlineMaxSleep     = 30 * time.Second // 单次最长睡眠(便于周期复查终态)

	drainFrontierPoll  = 2 * time.Second  // 目标达成后排空 OPEN 前沿的轮询间隔
	drainFrontierStall = 15 * time.Minute // 排空期间 open 数在此时长内零进展则放弃(worker 卡死兜底)
)

// ---------- settling 状态 ----------

func (e *Engine) isSettling(taskID string) bool {
	v, _ := e.settling.Load(taskID)
	b, _ := v.(bool)
	return b
}

// markSettling flips settling on; returns true only for the first caller.
func (e *Engine) markSettling(taskID string) bool {
	_, loaded := e.settling.LoadOrStore(taskID, true)
	return !loaded
}

// ---------- 在跑计数(worker.Execute + planner.Plan),用于 drain ----------

func (e *Engine) inflightCounter(taskID string) *int64 {
	v, _ := e.inflight.LoadOrStore(taskID, new(int64))
	return v.(*int64)
}
func (e *Engine) incInflight(taskID string) { atomic.AddInt64(e.inflightCounter(taskID), 1) }
func (e *Engine) decInflight(taskID string) { atomic.AddInt64(e.inflightCounter(taskID), -1) }
func (e *Engine) inflightCount(taskID string) int64 {
	return atomic.LoadInt64(e.inflightCounter(taskID))
}

// ---------- deadline ----------

// taskDeadline returns the task's absolute deadline (unix). Prefers the in-process
// map (stamped this session); falls back to the DB-loaded value (restart), seeding
// the map. 0 = no timeout / not yet stamped.
func (e *Engine) taskDeadline(t *Task) int64 {
	if v, ok := e.deadline.Load(t.ID); ok {
		return v.(int64)
	}
	if t.DeadlineAt > 0 {
		e.deadline.Store(t.ID, t.DeadlineAt)
		return t.DeadlineAt
	}
	return 0
}

// stampFirstRun records first_run_at + deadline_at on the FIRST real run (LLM ready)
// of a timeout task, once per process. No-op when the task has no timeout.
func (e *Engine) stampFirstRun(t *Task) {
	if t.TimeoutSeconds <= 0 {
		return
	}
	if _, loaded := e.stamped.LoadOrStore(t.ID, true); loaded {
		return
	}
	dl, err := e.m.StampTaskFirstRun(t.ID)
	if err != nil {
		log.Printf("[deadline] task %s 盖章 first_run 失败: %v", t.ID, err)
		e.stamped.Delete(t.ID) // 允许下次重试
		return
	}
	if dl > 0 {
		e.deadline.Store(t.ID, dl)
		log.Printf("[deadline] task %s 首次运行,截止于 %s", t.ID, time.Unix(dl, 0).Format("2006-01-02 15:04:05"))
	}
}

// clockCtx layers the task's TaskClock (absolute deadline) onto a run's context so
// worker/planner can clamp their wall-clock budget and pick per-run vs task-timeout
// wrap-up words. final marks the coordinator-driven terminal planner round.
func (e *Engine) clockCtx(base context.Context, t *Task, final bool) context.Context {
	dl := e.taskDeadline(t)
	if dl <= 0 && !final {
		return base // no timeout → unchanged behavior
	}
	return agent.WithTaskClock(base, agent.TaskClock{DeadlineUnix: dl, Final: final})
}

// ---------- 协调器 ----------

// startDeadlineCoordinator launches the per-task deadline timer once (idempotent).
// Called from Run() and from the restart reload path, so non-active timeout tasks
// still get settled after their deadline even without live planner/worker loops.
func (e *Engine) startDeadlineCoordinator(ctx context.Context, t *Task) {
	if t == nil || t.TimeoutSeconds <= 0 {
		return
	}
	if _, loaded := e.coordStarted.LoadOrStore(t.ID, true); loaded {
		return
	}
	go e.deadlineCoordinator(ctx, t)
}

// deadlineCoordinator waits until the task's absolute deadline, then runs the settle
// sequence. Absolute wall-clock: it keeps counting through pauses.
func (e *Engine) deadlineCoordinator(ctx context.Context, t *Task) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			return // already finished (goals met / failed) — nothing to time out
		}
		dl := e.taskDeadline(t)
		if dl <= 0 {
			if sleepCtx(ctx, deadlinePollInterval) { // not yet stamped (task hasn't really run)
				return
			}
			continue
		}
		if remaining := time.Until(time.Unix(dl, 0)); remaining > 0 {
			nap := remaining
			if nap > deadlineMaxSleep {
				nap = deadlineMaxSleep
			}
			if sleepCtx(ctx, nap) {
				return
			}
			continue
		}
		e.settleTask(ctx, t)
		return
	}
}

// drainInflight waits for a task's in-flight workers to finish their current
// round — so their results are written back while the task is still active —
// before closure, bounded by settleDrainGrace; past the grace it hard-cancels
// the exec context. Returns true if the engine is shutting down and the caller
// should bail. Shared by the timeout settle sequence (step ④) and the goals-met
// closure, so both paths drain gracefully instead of discarding live work.
func (e *Engine) drainInflight(ctx context.Context, t *Task) (engineStopping bool) {
	hardStop := time.Now().Add(settleDrainGrace)
	for e.inflightCount(t.ID) > 0 {
		if time.Now().After(hardStop) {
			log.Printf("[drain] task %s drain 超时(%s),硬取消在跑 run", t.ID, settleDrainGrace)
			e.cancelExec(t.ID)
			_ = sleepCtx(ctx, 3*time.Second) // 给 worker 分支一点时间落库/归类
			return false
		}
		if sleepCtx(ctx, 500*time.Millisecond) {
			return true // 引擎整体关停
		}
	}
	return false
}

// drainFrontier lets the worker pool execute the OPEN intents the planner already
// dispatched, AFTER all goals are met but BEFORE the task is closed, so a breadth-heavy
// frontier is not orphaned the instant the last goal is proven (the task-58 waste: 38
// already-dispatched IDOR/NoSQL/JWT/exposure intents thrown away). See docs/ROADMAP.md 4d.
//
// It is called from the planner loop's goals-met branch, so while it blocks, the planner
// is stopped and adds NO new intents: the OPEN frontier is frozen and can only shrink as
// workers claim it. The task is deliberately NOT yet terminal/settling here, which is
// exactly why workerLoop keeps claiming (it stops claiming on both of those states).
//
// Bound (option B, the chosen design): drain until the frontier empties OR until `cap`
// already-dispatched intents have been worked off (whichever first) — cap is
// GoalMetDrainCap. cap<=0 disables draining (immediate close, the pre-4c behavior). A
// no-progress stall timeout keeps a wedged worker from hanging closure forever; ctx
// (engine shutdown) and user-pause also end the wait. Absolute wall-clock is left to the
// task-level timeout (timeout_seconds), which is orthogonal and still applies.
func (e *Engine) drainFrontier(ctx context.Context, t *Task, cap int) {
	if cap <= 0 || t.Store == nil {
		return
	}
	open0, err := t.Store.OpenIntentCount()
	if err != nil || open0 == 0 {
		return // nothing queued → close immediately (clean finish, no change)
	}
	// floor: stop once the open count has dropped BY cap (cap intents drained) or reached
	// 0 (frontier fully emptied), whichever comes first.
	floor := open0 - cap
	if floor < 0 {
		floor = 0
	}
	log.Printf("[drain-frontier] task %s 目标达成，收尾前排空前沿: open=%d, 上限=%d → 排到剩 %d", t.ID, open0, cap, floor)
	lastOpen := open0
	lastProgress := time.Now()
	for {
		if sleepCtx(ctx, drainFrontierPoll) {
			return // 引擎整体关停
		}
		if e.IsPaused(t.ID) {
			log.Printf("[drain-frontier] task %s 排空期间被暂停,停止等待", t.ID)
			return
		}
		open, err := t.Store.OpenIntentCount()
		if err != nil {
			return
		}
		if open <= floor && e.inflightCount(t.ID) == 0 {
			log.Printf("[drain-frontier] task %s 前沿已排空(open=%d),收尾", t.ID, open)
			return
		}
		if open < lastOpen {
			lastOpen = open
			lastProgress = time.Now()
		}
		if time.Since(lastProgress) > drainFrontierStall {
			log.Printf("[drain-frontier] task %s 排空停滞 %s 无进展(open=%d),强制收尾", t.ID, drainFrontierStall, open)
			return
		}
	}
}

// settleTask runs the ordered settle sequence once (§4 steps ①–⑥).
func (e *Engine) settleTask(ctx context.Context, t *Task) {
	if !e.markSettling(t.ID) {
		return
	}
	log.Printf("[deadline] task %s 到达超时上限,进入收尾时序", t.ID)

	// ④ drain 在跑 worker/planner(graceful，见 drainInflight)；超过 grace → 硬 cancel。
	if e.drainInflight(ctx, t) {
		return // 引擎整体关停
	}

	// ⑤ 终局一轮 planner(任务超时词,最后目标判定,不产新意图)。
	met := e.runFinalPlannerRound(ctx, t)

	// ⑥ 定终态(带守卫):met → done(completed);否则 timeout。若常规路径已先落 done,
	// 守卫(SetTaskStatusGuarded)会拒绝覆盖,保留 completed 语义。
	status := "timeout"
	if met {
		status = "done"
	}
	won, err := e.m.SetTaskStatusGuarded(t.ID, status)
	switch {
	case err != nil:
		log.Printf("[deadline] task %s 落终态失败: %v", t.ID, err)
	case won:
		log.Printf("[deadline] task %s 收尾完成,终态=%s", t.ID, status)
	default:
		log.Printf("[deadline] task %s 收尾时已是终态,保留原状态", t.ID)
	}
}

// runFinalPlannerRound drives exactly ONE terminal planner round with the
// task-timeout planner words (final goal judgment; no new intents). Waits for the
// LLM to be ready (bounded by ctx) so a completable task isn't mis-judged timeout.
func (e *Engine) runFinalPlannerRound(ctx context.Context, t *Task) (met bool) {
	planner, _ := e.snapshotFor(t)
	for planner == nil {
		if sleepCtx(ctx, deadlinePollInterval) {
			return false
		}
		if isTerminalStatus(e.m.TaskStatus(t.ID)) {
			return false
		}
		planner, _ = e.snapshotFor(t)
	}
	emit := func(r db.Activity) { e.emitActivity(t, r) }
	e.emitActivity(t, db.Activity{Worker: "planner", Kind: "round",
		Summary: fmt.Sprintf("Chiusura per timeout del task · giudizio finale (giro %d)", e.nextPlannerRound(t.ID))})
	// 独立 ctx(不挂 execCancel,避免 pause/硬 cancel 打断这最后一轮),带 Final 注入任务超时词。
	fctx := e.clockCtx(ctx, t, true)
	e.incInflight(t.ID)
	tTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
	met, reason, err := planner.Plan(fctx, tTaskID, e.m.assets, t.Store, t.Goal, t.drainDone(), emit)
	e.decInflight(t.ID)
	if err != nil {
		log.Printf("[deadline] task %s 终局规划出错: %v", t.ID, err)
	} else if met {
		log.Printf("[deadline] task %s 终局判定目标达成: %s", t.ID, reason)
	}
	return met
}
