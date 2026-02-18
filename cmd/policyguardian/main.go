package main

import (
	"os"
	"policyguardian/internal/shared/cliapp"
)

func main(){ os.Exit(cliapp.Run(os.Args[1:])) }
