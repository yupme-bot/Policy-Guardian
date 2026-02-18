package main

import (
	"os"
	"policyguardian/internal/shared/cliapp"
)

func main(){ args := append([]string{"consent"}, os.Args[1:]...); os.Exit(cliapp.Run(args)) }
