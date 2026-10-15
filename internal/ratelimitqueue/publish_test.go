package ratelimitqueue

import (
	"errors"
	"fmt"
	"testing"
)

type fakePusher struct {
	pushed    []string
	trimCalls [][3]any
	failOn    int // 1-based push number that fails; 0 = none
}

func (f *fakePusher) Push(key, value string) error {
	if f.failOn > 0 && len(f.pushed)+1 == f.failOn {
		f.failOn = 0
		return errors.New("boom")
	}
	f.pushed = append(f.pushed, key+"|"+value)
	return nil
}

func (f *fakePusher) Trim(key string, start, stop int) error {
	f.trimCalls = append(f.trimCalls, [3]any{key, start, stop})
	return nil
}

func TestPublishPushesThenCapsTheList(t *testing.T) {
	f := &fakePusher{}
	n, err := Publish(f, []Event{{Pool: "a", Status: 429}, {Pool: "b", Status: 429}})
	if err != nil || n != 2 || len(f.pushed) != 2 {
		t.Fatalf("n=%d err=%v pushed=%d", n, err, len(f.pushed))
	}
	if len(f.trimCalls) != 1 || f.trimCalls[0] != [3]any{QueueKey, -MaxQueueEvents, -1} {
		t.Errorf("trim calls = %v, want one LTRIM %s -%d -1", f.trimCalls, QueueKey, MaxQueueEvents)
	}
}

func TestPublishNoEventsDoesNotTouchRedis(t *testing.T) {
	f := &fakePusher{}
	if n, err := Publish(f, nil); n != 0 || err != nil || len(f.trimCalls) != 0 {
		t.Errorf("n=%d err=%v trims=%d", n, err, len(f.trimCalls))
	}
}

func TestPublishSkipsAFailedPushButKeepsGoing(t *testing.T) {
	f := &fakePusher{failOn: 1}
	n, err := Publish(f, []Event{{Pool: "a"}, {Pool: "b"}, {Pool: "c"}})
	if err == nil {
		t.Error("the failed push must be reported")
	}
	if n != 2 || len(f.pushed) != 2 {
		t.Errorf("stored %d (pushed %d), want 2 of 3", n, len(f.pushed))
	}
	if len(f.trimCalls) != 1 {
		t.Errorf("trim calls = %d, want 1 after a partial success", len(f.trimCalls))
	}
}

func TestPublishAllFailingSkipsTrim(t *testing.T) {
	f := &failingPusher{}
	n, err := Publish(f, []Event{{Pool: "a"}})
	if n != 0 || err == nil {
		t.Errorf("n=%d err=%v", n, err)
	}
	if f.trims != 0 {
		t.Error("nothing was stored, so there is nothing to trim")
	}
}

type failingPusher struct{ trims int }

func (f *failingPusher) Push(string, string) error { return fmt.Errorf("down") }
func (f *failingPusher) Trim(string, int, int) error {
	f.trims++
	return nil
}
