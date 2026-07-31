//go:build darwin

package main

import "golang.org/x/sys/unix"

func atomicExchangeInputTemplate(left, right string) error {
	return unix.RenameatxNp(
		unix.AT_FDCWD,
		left,
		unix.AT_FDCWD,
		right,
		unix.RENAME_SWAP,
	)
}

func atomicPublishReviewPacketDirectory(staging, target string) error {
	return unix.RenameatxNp(
		unix.AT_FDCWD,
		staging,
		unix.AT_FDCWD,
		target,
		unix.RENAME_EXCL,
	)
}
