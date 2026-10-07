//go:build !darwin

package main

import "errors"

func probe() error {
	return errors.New("NOT_RUN_REQUIRES_MAC: native utun probe cannot run on this platform")
}
