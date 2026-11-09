package db

import (
	"testing"
	"testing/fstest"
)

func TestLoadMigrationsValidatesNames(t *testing.T) {
	good := fstest.MapFS{
		"m/0002_b.sql": {Data: []byte("SELECT 2;")},
		"m/0001_a.sql": {Data: []byte("SELECT 1;")},
	}
	ms, err := LoadMigrationsFrom(good, "m")
	if err != nil || len(ms) != 2 || ms[0].Name != "a" || ms[1].Version != 2 {
		t.Fatalf("sorted load: %+v %v", ms, err)
	}
	for name, fsys := range map[string]fstest.MapFS{
		"bad name":  {"m/1_a.sql": {Data: []byte("x")}},
		"uppercase": {"m/0001_A.sql": {Data: []byte("x")}},
		"duplicate": {"m/0001_a.sql": {Data: []byte("x")}, "m/0001_b.sql": {Data: []byte("y")}},
	} {
		if _, err := LoadMigrationsFrom(fsys, "m"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
