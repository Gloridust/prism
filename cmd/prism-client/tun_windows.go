package main

import "fmt"

const tunMTU = 1500

type tunDevice struct {
	name string
}

func openTUN(name string) (*tunDevice, error) {
	return nil, fmt.Errorf("TUN mode on Windows requires the wintun driver; not yet implemented")
}

func (t *tunDevice) Read(buf []byte) (int, error)  { return 0, fmt.Errorf("not implemented") }
func (t *tunDevice) Write(buf []byte) (int, error) { return 0, fmt.Errorf("not implemented") }
func (t *tunDevice) Close() error                  { return nil }
func (t *tunDevice) Name() string                  { return t.name }

func configureTUN(dev *tunDevice, addr, gateway string) error {
	return fmt.Errorf("TUN not implemented on Windows")
}

func addDefaultRoute(dev *tunDevice, serverAddr, origGateway string) error {
	return fmt.Errorf("TUN not implemented on Windows")
}

func removeDefaultRoute(serverAddr, origGateway string) {}

func tunRouter(dev *tunDevice, dialer *Dialer) {}
