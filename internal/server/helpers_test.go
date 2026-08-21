package server

import (
	"time"
)

func timeHour() time.Duration { return time.Hour }

func sleepTiny() { time.Sleep(5 * time.Millisecond) }
