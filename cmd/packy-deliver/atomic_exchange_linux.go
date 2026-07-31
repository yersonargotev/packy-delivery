//go:build linux

package main

import "golang.org/x/sys/unix"

func atomicExchangeInputTemplate(left, right string) error {
	return unix.Renameat2(
		unix.AT_FDCWD,
		left,
		unix.AT_FDCWD,
		right,
		unix.RENAME_EXCHANGE,
	)
}

func atomicPublishReviewPacketDirectory(staging, target string) error {
	return unix.Renameat2(
		unix.AT_FDCWD,
		staging,
		unix.AT_FDCWD,
		target,
		unix.RENAME_NOREPLACE,
	)
}
