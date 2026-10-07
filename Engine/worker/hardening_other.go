//go:build !darwin

package main

func disableCoreDumps() error { return nil }
