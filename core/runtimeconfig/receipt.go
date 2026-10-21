package runtimeconfig

import (
	"bytes"
	"errors"
)

func clonePayloads(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, p := range in {
		out[i] = append([]byte(nil), p...)
	}
	return out
}
func (s *Store) Receipt() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.receipts) == 0 {
		return nil
	}
	return append([]byte(nil), s.receipts[0]...)
}
func (s *Store) QueueReceipt(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.receipts) >= 1024 {
		return errors.New("runtime receipt outbox is full")
	}
	next := append(clonePayloads(s.receipts), append([]byte(nil), payload...))
	if err := s.persist(persistedState{Current: s.Current(), Previous: s.previous, Receipts: next}); err != nil {
		return err
	}
	s.receipts = next
	return nil
}
func (s *Store) FinishReceipt(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.receipts) == 0 || !bytes.Equal(payload, s.receipts[0]) {
		return nil
	}
	next := clonePayloads(s.receipts[1:])
	if err := s.persist(persistedState{Current: s.Current(), Previous: s.previous, Receipts: next}); err != nil {
		return err
	}
	s.receipts = next
	return nil
}
