package refusal

import (
	"encoding/json"
	"fmt"
	"io"

	"laneboss.io/laneboss/internal/eventstore"
)

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := "usage: laneboss refusal report --config NAME [--refusal ID | --rule ID] [--effect CLASS] --note TEXT\n       laneboss refusal proposals --config NAME"
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	action := args[0]
	values := map[string]string{}
	for i := 1; i < len(args); i++ {
		key := args[i]
		if (key != "--config" && key != "--refusal" && key != "--rule" && key != "--effect" && key != "--note") || i+1 == len(args) || values[key] != "" {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		i++
		values[key] = args[i]
	}
	if values["--config"] == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	var result any
	var err error
	if action == "report" {
		result, err = Report(values["--config"], Request{Refusal: values["--refusal"], Rule: values["--rule"], Effect: values["--effect"], Note: values["--note"]}, "cli")
	} else if action == "proposals" {
		var binding *eventstore.Configuration
		binding, err = eventstore.Bind(values["--config"])
		if err == nil {
			var events []object
			_, events, err = eventstore.ReadDisplay(binding)
			if err == nil {
				result = Proposals(events)
			}
		}
	} else {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "refused: proposal records could not be read or recorded")
		return 2
	}
	if err = json.NewEncoder(stdout).Encode(eventstore.ScreenValue(result)); err != nil {
		return 70
	}
	return 0
}
