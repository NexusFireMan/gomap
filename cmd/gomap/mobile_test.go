package gomap

import "testing"

func TestCLIMobileOptions(t *testing.T) {
	for _, tc := range []struct {
		args            []string
		mobile, rateSet bool
		rate            int
	}{
		{args: []string{"127.0.0.1"}},
		{args: []string{"--mobile", "127.0.0.1"}, mobile: true},
		{args: []string{"127.0.0.1", "--mobile", "--global-rate=0"}, mobile: true, rateSet: true},
		{args: []string{"--mobile=false", "--global-rate", "25", "127.0.0.1"}, rateSet: true, rate: 25},
	} {
		got, err := ParseCLIOptions(tc.args)
		if err != nil || got.Mobile != tc.mobile || got.GlobalRateSet != tc.rateSet || got.GlobalRate != tc.rate {
			t.Fatalf("%v: got %+v, %v", tc.args, got, err)
		}
	}
	for _, args := range [][]string{
		{"--mobile", "--global-rate=-1", "127.0.0.1"},
		{"--mobile", "--workers=-1", "127.0.0.1"},
		{"--mobile=invalid", "127.0.0.1"},
	} {
		if _, err := ParseCLIOptions(args); err == nil {
			t.Fatalf("accepted invalid options: %v", args)
		}
	}
}
