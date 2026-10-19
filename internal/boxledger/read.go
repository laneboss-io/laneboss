package boxledger

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

func decodeObject(line []byte, exact bool) (map[string]any, bool) {
	if !utf8.Valid(line) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	if exact {
		decoder.UseNumber()
	}
	var row map[string]any
	if err := decoder.Decode(&row); err != nil || row == nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return row, true
}

func (l *Ledger) readEvents(exact bool) (events []map[string]any, tail bool, err error) {
	events = make([]map[string]any, 0)
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return events, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	reader := bufio.NewReader(f)
	for number := 1; ; number++ {
		line, readErr := reader.ReadBytes('\n')
		if readErr != nil && readErr != io.EOF {
			return nil, false, readErr
		}
		if len(line) != 0 {
			tail = line[len(line)-1] != '\n'
			if row, valid := decodeObject(line, exact); valid {
				events = append(events, row)
			} else {
				if _, noteErr := fmt.Fprintf(l.notes, "%s: line %d: skipped invalid event\n", l.path, number); noteErr != nil {
					return nil, false, noteErr
				}
			}
		}
		if readErr == io.EOF {
			return events, tail, nil
		}
	}
}

func nextSequence(events []map[string]any) (any, error) {
	// Exact decimals keep integer sequences correct beyond float64's precision.
	highest := new(big.Rat)
	scale := 0
	found := false
	for _, row := range events {
		number, numeric := row["seq"].(json.Number)
		if !numeric {
			continue
		}
		value, ok := new(big.Rat).SetString(number.String())
		if !ok {
			return nil, errors.New("ledger seq: cannot represent numeric sequence")
		}
		if found && value.Cmp(highest) <= 0 {
			continue
		}
		highest.Set(value)
		found = true
		text := number.String()
		exponent := 0
		if index := strings.IndexAny(text, "eE"); index >= 0 {
			var err error
			exponent, err = strconv.Atoi(text[index+1:])
			if err != nil {
				return nil, errors.New("ledger seq: exponent is outside the supported bounds")
			}
			text = text[:index]
		}
		scale = 0
		if index := strings.IndexByte(text, '.'); index >= 0 {
			scale = len(text) - index - 1
		}
		scale = max(0, scale-exponent)
	}
	highest.Add(highest, big.NewRat(1, 1))
	if highest.IsInt() {
		if highest.Num().IsInt64() {
			return highest.Num().Int64(), nil
		}
		return json.Number(highest.Num().String()), nil
	}
	text := strings.TrimRight(strings.TrimRight(highest.FloatString(scale), "0"), ".")
	return json.Number(text), nil
}
