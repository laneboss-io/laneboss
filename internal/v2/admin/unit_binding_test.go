package admin

import "testing"

func TestHelperControlUnitSelection(t *testing.T) {
	for _, config := range []string{"admin-case", "another-case"} {
		actual, err := helperControlConfig("/system.slice/laneboss-helper@" + "" + config + ".service/control")
		if err != nil || actual != config {
			t.Fatal("installed canary selected a guessed instance instead of its unit binding", err)
		}
	}
	for _, membership := range []string{"/user.slice/session.scope", "/system.slice/laneboss-service@" + "admin-case.service/control", "/system.slice/laneboss-helper@" + "admin-case.service", "/system.slice/laneboss-helper@" + "../admin-case.service/control"} {
		if _, err := helperControlConfig(membership); err == nil {
			t.Fatal("installed canary accepted a foreign or unbounded control unit")
		}
	}
}
