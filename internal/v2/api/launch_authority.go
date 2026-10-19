package api

// ValidateLaunchReservationRequest closes the private reservation path's shape
// gates. The store still verifies/consumes real authority and checks current
// receipt, child subset, target epoch and ticket/proof provenance atomically.
func ValidateLaunchReservationRequest(scope Scope, request LaunchReservationRequest) error {
	if request.Loop != nil {
		return validateLoopRequest(scope, request)
	}
	if !launchID(request.OperationID) || !bindingConfigName.MatchString(scope.Config) || !launchID(scope.Actor.ID) {
		return launchInvalid("invalid launch reservation request")
	}
	tickets, proofs, cancellations := 0, 0, 0
	var ticket *TicketUse
	var proof *ProofUse
	var cancellation *CancellationCheck
	for _, guard := range request.Guards {
		count := 0
		if guard.Ticket != nil {
			count++
			tickets++
			ticket = guard.Ticket
		}
		if guard.Proof != nil {
			count++
			proofs++
			proof = guard.Proof
		}
		if guard.Cancellation != nil {
			count++
			cancellations++
			cancellation = guard.Cancellation
		}
		if guard.Approval != nil {
			count++
		}
		if count != 1 || guard.Approval != nil {
			return launchInvalid("invalid launch reservation guard union")
		}
	}
	if scope.Actor.Kind == "lane" && (scope.Request.Proof != nil || proofs != 0 || tickets != 0) {
		return launchInvalid("lane reservation cannot carry human proof or ticket")
	}
	if request.ContinuationID != "" {
		if !launchID(request.ContinuationID) || scope.Request.Method != "" ||
			scope.Request.Proof != nil ||
			scope.Actor.Kind != "service" && scope.Actor.Kind != "scheduler" && scope.Actor.Kind != "watchdog" ||
			proofs != 0 || tickets != 0 || cancellations != 1 || !launchID(cancellation.LifeID) || cancellation.Epoch > launchMaxInteger {
			return launchInvalid("invalid continuation reservation authority")
		}
		return nil
	}
	frame := scope.Request
	digest, err := RequestDigest(frame)
	if err != nil || frame.Protocol != Protocol || frame.Schema != SchemaVersion || frame.Config != scope.Config ||
		!launchID(frame.RequestID) || !launchID(frame.IdempotencyKey) || frame.RequestSHA256 != digest || !launchGeneration(scope.PolicyGeneration) ||
		scope.Actor.Kind != "human" && scope.Actor.Kind != "lane" {
		return launchInvalid("reservation request lacks its authenticated original frame")
	}
	var level int
	var role string
	var ticketID ID
	var target LifeRef
	var base Generation
	switch frame.Method {
	case "lane.start":
		var body StartRequest
		if DecodeObject(frame.Params, &body) != nil {
			return launchInvalid("invalid start reservation body")
		}
		level, role, ticketID = body.Level, body.Role, body.RootTicketID
	case "lane.adopt":
		var body AdoptRequest
		if DecodeObject(frame.Params, &body) != nil {
			return launchInvalid("invalid adopt reservation body")
		}
		level, role, ticketID = body.Level, body.Role, body.RootTicketID
	case "lane.resume":
		var body ResumeRequest
		if DecodeObject(frame.Params, &body) != nil {
			return launchInvalid("invalid resume reservation body")
		}
		target, base = body.Target, body.ExpectedGeneration
	case "lane.turn":
		var body TurnRequest
		if DecodeObject(frame.Params, &body) != nil {
			return launchInvalid("invalid turn reservation body")
		}
		target, base = body.Target, body.ExpectedGeneration
	default:
		return launchInvalid("method cannot reserve a launch")
	}
	if frame.Method == "lane.start" || frame.Method == "lane.adopt" {
		if level < 3 || level > 6 || !launchID(ID(role)) {
			return launchInvalid("invalid reserved child role")
		}
		if scope.Actor.Kind == "human" {
			if proofs != 0 || frame.Proof != nil || cancellations != 0 || !launchID(ticketID) || !launchGeneration(scope.EndpointGeneration) {
				return launchInvalid("invalid root reservation authority")
			}
			if tickets != 1 {
				return launchInvalid("human root reservation requires its ticket use")
			}
			if ticket != nil && (ticket.TicketID != ticketID ||
				ticket.PrincipalID != scope.Actor.ID || ticket.Config != scope.Config ||
				ticket.EndpointGeneration != scope.EndpointGeneration || ticket.Level != level || ticket.Role != role || !launchID(ticket.GrantSetID) ||
				ticket.Target != (LifeRef{})) {
				return launchInvalid("root reservation ticket differs from authenticated scope")
			}
		} else if scope.Actor.Level > 6 || scope.Actor.Level <= level || !launchID(scope.Actor.LifeID) || ticketID != "" {
			return launchInvalid("reserved child is outside its authentic starter")
		}
		return nil
	}
	if cancellations != 1 || !launchID(target.LifeID) || target.Run == 0 || !launchGeneration(base) ||
		cancellation.LifeID != target.LifeID || cancellation.Epoch > launchMaxInteger || tickets != 0 {
		return launchInvalid("retained-life reservation requires its cancellation fence")
	}
	if scope.Actor.Kind == "human" {
		if proofs != 1 || frame.Proof == nil || proof.Proof != *frame.Proof || !launchID(proof.Proof.ID) || proof.Proof.RequestSHA256 != digest ||
			proof.Target.Method != frame.Method || proof.Target.TargetID != target.LifeID || proof.Target.RequestSHA256 != digest || proof.Target.BaseGeneration != base {
			return launchInvalid("human retained-life reservation requires its operation proof")
		}
	}
	return nil
}
