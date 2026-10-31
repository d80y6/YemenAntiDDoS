package action

// WaitIdle covers only synchronous dispatch, not action/webhook goroutines.
func (e *Engine) WaitIdle() { e.drain(nil) }

// Call after releasing all barriers and joining every sender/Drain caller.
// Wakes an idle dispatcher and joins it; production cannot call this method.
func (e *Engine) stop() { close(e.testStop); <-e.dispatchDone }
