//go:build !darwin && !linux

package main

import "errors"

func atomicExchangeInputTemplate(_, _ string) error {
	return errors.New("atomic regular-file replacement is unsupported on this platform")
}

func atomicPublishReviewPacketDirectory(_, _ string) error {
	return errors.New("atomic review-packet directory publication is unsupported on this platform")
}
