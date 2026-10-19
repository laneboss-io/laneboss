package store

import (
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestLaunchPromptRequestPins(t *testing.T) {
	startReservation := api.LaunchReservation{Mode: "start", Level: 3, Role: "executor", Driver: api.DriverCodex, PolicyGeneration: 7}
	plan := api.LaunchPlanRecord{Inputs: &api.LaunchInputs{Sources: api.LaunchSources{Project: api.ProjectLaunchSource{ProjectID: "project"}}}}
	start := api.StartRequest{ProjectID: "project", Level: 3, Role: "executor", Driver: api.DriverCodex, ExpectedPolicyGeneration: 7}
	if err := launchPromptStartPins(startReservation, plan, start); err != nil {
		t.Fatal(err)
	}
	start.ProjectID = "foreign-project"
	if err := launchPromptStartPins(startReservation, plan, start); err == nil {
		t.Fatal("start project pin was ignored")
	}

	adopt := api.AdoptRequest{Level: 3, Role: "executor", Driver: api.DriverCodex, ExpectedPolicyGeneration: 7}
	if err := launchPromptAdoptPins(startReservation, adopt); err != nil {
		t.Fatal(err)
	}
	adopt.Role = "reviewer"
	if err := launchPromptAdoptPins(startReservation, adopt); err == nil {
		t.Fatal("adoption role pin was ignored")
	}

	retained := api.LaunchReservation{Mode: "resume", Target: api.LifeRef{LifeID: "life", Run: 4}, BaseGeneration: 3}
	resume := api.ResumeRequest{Target: api.LifeRef{LifeID: "life", Run: 3}, ExpectedGeneration: 3}
	previous := api.Lane{Level: 3, Role: "executor", Session: api.Session{Driver: api.DriverCodex}}
	retained.Level, retained.Role, retained.Driver = previous.Level, previous.Role, previous.Session.Driver
	if err := launchPromptResumePins(retained, resume, previous); err != nil {
		t.Fatal(err)
	}
	resume.ExpectedGeneration++
	if err := launchPromptResumePins(retained, resume, previous); err == nil {
		t.Fatal("resume generation pin was ignored")
	}

	turnReservation := retained
	turnReservation.Mode = "turn"
	turn := api.TurnRequest{Target: api.LifeRef{LifeID: "life", Run: 3}, ExpectedGeneration: 3, MailIDs: []api.ID{}}
	if err := launchPromptTurnPins(turnReservation, turn, previous); err != nil {
		t.Fatal(err)
	}
	turn.Target.LifeID = "foreign-life"
	if err := launchPromptTurnPins(turnReservation, turn, previous); err == nil {
		t.Fatal("turn target pin was ignored")
	}
}

func TestPromptClosedTriggers(t *testing.T) {
	manual, manualIDs, err := launchPromptTrigger("resume", nil)
	if err != nil || manual.Kind != "manual" || len(manual.MailIDs) != 0 || len(manualIDs) != 0 {
		t.Fatalf("resume trigger was not manual: %+v, %v", manual, err)
	}
	mail, mailIDs, err := launchPromptTrigger("turn", []api.ID{"mail-a"})
	if err != nil || mail.Kind != "mail" || !reflect.DeepEqual(mail.MailIDs, []api.ID{"mail-a"}) || !reflect.DeepEqual(mailIDs, []api.ID{"mail-a"}) {
		t.Fatalf("mail turn trigger lost its ordered IDs: %+v, %v", mail, err)
	}
	idle, idleIDs, err := launchPromptTrigger("turn", nil)
	if err != nil || idle.Kind != "idle" || len(idle.MailIDs) != 0 || len(idleIDs) != 0 {
		t.Fatalf("idle turn trigger was not closed-schema idle: %+v, %v", idle, err)
	}
}
