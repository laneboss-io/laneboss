package api

// IssuedLaunchProfile maps a protected start/adopt request's template member
// selector to the corresponding retained issued member. Issuance preserves
// request order; roots clear ParentGrantID, while child delegations retain it.
// Callers authenticate the original frame and issued set before using this
// pure mapping. Possession of either ID grants no authority.
func IssuedLaunchProfile(r LaunchReservation, original Request, issued GrantSet) (ProfileGrant, error) {
	refuse := func(message string) (ProfileGrant, error) {
		return ProfileGrant{}, &Error{Code: CodeForbidden, Owner: "lb-v2-grants", Message: message}
	}
	var selected ID
	var requested []ProfileDelegation
	switch r.Mode {
	case "start":
		var input StartRequest
		if original.Method != "lane.start" || DecodeObject(original.Params, &input) != nil {
			return refuse("profile selection requires the retained start frame")
		}
		selected, requested = input.ProfileGrantID, input.Grants.Profiles
	case "adopt":
		var input AdoptRequest
		if original.Method != "lane.adopt" || DecodeObject(original.Params, &input) != nil {
			return refuse("profile selection requires the retained adoption frame")
		}
		selected, requested = input.ProfileGrantID, input.Grants.Profiles
	default:
		return refuse("issued profile mapping requires a new launch reservation")
	}
	digest, err := RequestDigest(original)
	if err != nil || original.Config != r.Config || original.RequestID != r.RequestID || original.RequestSHA256 != r.RequestSHA256 || digest != r.RequestSHA256 ||
		issued.ID != r.GrantSetID || issued.LifeID != r.Target.LifeID || issued.ParentLifeID != r.ParentLifeID || issued.PolicyGeneration != r.PolicyGeneration ||
		!launchID(selected) || len(issued.Profiles) != len(requested) {
		return refuse("issued profile inventory differs from the retained reservation and request")
	}
	index := -1
	for i, entry := range requested {
		if entry.ParentGrantID == selected {
			if index != -1 {
				return refuse("original profile selector is ambiguous")
			}
			index = i
		}
	}
	if index < 0 {
		return refuse("original profile selector was not delegated")
	}
	want, member := requested[index], issued.Profiles[index]
	parent := selected
	if r.ParentLifeID == "" {
		parent = ""
	}
	if !launchID(member.ID) || member.ParentGrantID != parent || member.ProfileID != want.ProfileID || member.Driver != r.Driver ||
		member.ExpiresAt != want.ExpiresAt || member.Delegate != want.Delegate {
		return refuse("issued profile differs from its retained template selection")
	}
	matches := 0
	for _, entry := range issued.Profiles {
		if entry.ID == member.ID {
			matches++
		}
	}
	if matches != 1 {
		return refuse("issued profile member is not unique")
	}
	return member, nil
}
