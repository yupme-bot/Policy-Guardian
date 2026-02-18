package main

import (
	"fmt"
	"os"

	"policyguardian/internal/consentguardian"
	"policyguardian/internal/policylock"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: ref_verify policylock <snapshot.zip> | consent <consent.json>")
		os.Exit(4)
	}
	switch os.Args[1] {
	case "policylock":
		b, err := os.ReadFile(os.Args[2])
		if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(4) }
		st, reason, _ := policylock.VerifySnapshotZip(b)
		fmt.Println(st)
		if reason != "" { fmt.Println("reason:", reason) }
		if st != "VALID" { os.Exit(2) }
	case "consent":
		st, reason, _, err := consentguardian.VerifyConsentFile(os.Args[2], false)
		if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(4) }
		fmt.Println(st)
		if reason != "" { fmt.Println("reason:", reason) }
		if st == "INVALID" { os.Exit(2) }
		if st == "PARTIAL" { os.Exit(1) }
	default:
		fmt.Fprintln(os.Stderr, "unknown")
		os.Exit(4)
	}
}
