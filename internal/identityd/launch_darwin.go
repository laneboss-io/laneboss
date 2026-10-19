package identityd

func requireNoSubreaper() error {
	return refuse("Darwin lane mutations require verified peer lifetime support")
}

func replaceStdio() error { return processUnavailable() }
