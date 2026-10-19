package main

import (
	"fmt"
	"os"
)

func main() {
	for _, argument := range os.Args[1:] {
		fmt.Println(argument)
	}
}
