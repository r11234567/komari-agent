package qgastream

import (
	"bytes"
	"testing"
)

func TestFragmentedAndAdjacentFrames(t *testing.T) {
	var d Decoder
	var messages [][]byte
	collect := func(frame Frame) error {
		if frame.Lost {
			t.Fatal("valid frame was lost")
		}
		if frame.Bytes != nil {
			messages = append(messages, bytes.Clone(frame.Bytes))
		}
		return nil
	}
	input := []byte("\xff" + `{"execute":"first","arguments":{"text":"]}\\\""}}{"return":[1,2]}`)
	for _, b := range input {
		if err := d.Feed([]byte{b}, collect); err != nil {
			t.Fatal(err)
		}
	}
	if len(messages) != 2 || string(messages[1]) != `{"return":[1,2]}` {
		t.Fatalf("decoded %d frames", len(messages))
	}
}

func TestFrameLimitAndExplicitResync(t *testing.T) {
	var d Decoder
	var loss, reset, records int
	collect := func(frame Frame) error {
		if frame.Lost {
			loss++
		}
		if frame.Reset {
			reset++
		}
		if len(frame.Bytes) != 0 {
			records++
		}
		return nil
	}
	input := append([]byte(`{"return":"`), bytes.Repeat([]byte{'x'}, frameLimit)...)
	input = append(input, []byte(`"}{"return":1}`+"\xff"+`{"return":2}`)...)
	if err := d.Feed(input, collect); err != nil {
		t.Fatal(err)
	}
	if loss != 1 || reset != 1 || records != 1 {
		t.Fatalf("loss=%d reset=%d records=%d", loss, reset, records)
	}
}
