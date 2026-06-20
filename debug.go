package main

import (
	"log"
	"os"
	"sync/atomic"
)

var debugForced = os.Getenv("RAHGOZAR_DEBUG") != ""
var debugFlag atomic.Bool

func debugOn() bool { return debugForced || debugFlag.Load() }

func setDebugFlag(on bool) { debugFlag.Store(on) }

func dbg(format string, args ...any) {
	if debugOn() {
		log.Printf("[debug] "+format, args...)
	}
}
