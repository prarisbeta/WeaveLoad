package store

import "testing"

func TestGetSetting_NotFound(t *testing.T) {
	s := newTestDB(t)
	if _, err := s.GetSetting("nope"); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSetSetting_RoundTripAndOverwrite(t *testing.T) {
	s := newTestDB(t)
	if err := s.SetSetting("k", "v1"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	got, err := s.GetSetting("k")
	if err != nil || got != "v1" {
		t.Fatalf("GetSetting = %q, %v", got, err)
	}

	if err := s.SetSetting("k", "v2"); err != nil {
		t.Fatalf("SetSetting overwrite: %v", err)
	}
	got, err = s.GetSetting("k")
	if err != nil || got != "v2" {
		t.Fatalf("GetSetting after overwrite = %q, %v", got, err)
	}
}

func TestGetRedisSettings_DefaultsToZeroValueWhenUnset(t *testing.T) {
	s := newTestDB(t)
	rs, err := s.GetRedisSettings()
	if err != nil {
		t.Fatalf("GetRedisSettings: %v", err)
	}
	if rs != (RedisSettings{}) {
		t.Errorf("rs = %+v, want zero value", rs)
	}
}

func TestRedisSettings_RoundTrip(t *testing.T) {
	s := newTestDB(t)
	want := RedisSettings{Host: "10.0.0.5", Port: "6380", Password: "secret", DB: 2, TLS: true}
	if err := s.SetRedisSettings(want); err != nil {
		t.Fatalf("SetRedisSettings: %v", err)
	}
	got, err := s.GetRedisSettings()
	if err != nil {
		t.Fatalf("GetRedisSettings: %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
