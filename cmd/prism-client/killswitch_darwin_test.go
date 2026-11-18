package main

import "testing"

func ksRulesetText(p ksParams) string { return ksRuleset(p) }

func ksTestPrepare(t *testing.T) bool { return false }

func ksTestCrash(dev *tunDevice) { dev.Close() }
