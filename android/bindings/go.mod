module github.com/NexusFireMan/gomap/android/bindings

go 1.26.10

require github.com/NexusFireMan/gomap/v2 v2.0.0

require (
	github.com/gosnmp/gosnmp v1.45.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/mobile v0.0.0-20261117202452-47699113848a // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
)

replace github.com/NexusFireMan/gomap/v2 => ../..

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
