package main

import (
	"testing"

	"github.com/jeffbstewart/touchvault"
)

func TestChooseSlot(t *testing.T) {
	two := []touchvault.SlotInfo{
		{Slot: 0, Label: "yk-primary"},
		{Slot: 1, Label: "yk-backup"},
	}
	gap := []touchvault.SlotInfo{
		{Slot: 0, Label: "yk-primary"},
		{Slot: 2, Label: "yk-desktop"},
	}
	tests := []struct {
		name      string
		slots     []touchvault.SlotInfo
		requested int
		label     string
		want      int
		wantErr   bool
	}{
		{"lowest free after two", two, -1, "yk-laptop", 2, false},
		{"fills a gap", gap, -1, "yk-laptop", 1, false},
		{"explicit free slot", two, 7, "yk-laptop", 7, false},
		{"explicit occupied slot", two, 1, "yk-laptop", 0, true},
		{"duplicate label", two, -1, "yk-backup", 0, true},
		{"empty label", two, -1, "", 0, true},
		{"empty vault metadata", nil, -1, "yk-first", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := chooseSlot(tc.slots, tc.requested, tc.label)
			if (err != nil) != tc.wantErr {
				t.Fatalf("chooseSlot() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("chooseSlot() = %d, want %d", got, tc.want)
			}
		})
	}
}
