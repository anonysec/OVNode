package commands

// IsFake reports whether the fake runner recorded calls.
func IsFake() bool { return isFake() }

// HoldFake persists the recording-runner calls to OVNODE_FAKE_LOG.
func HoldFake(r Runner) { hold(r) }
