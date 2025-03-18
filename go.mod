module github.com/amnezia-vpn/amneziawg-windows-client

go 1.20

require (
	github.com/amnezia-vpn/amneziawg-go v0.2.16
	github.com/amnezia-vpn/amneziawg-windows v0.1.8
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/crypto v0.0.0-20220315160706-3147a52a75dd
	golang.org/x/sys v0.0.0-20220315194320-039c03cc5b86
	golang.org/x/text v0.3.8-0.20220124021120-d1c84af989ab
)

require (
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20210121140954-e7fc19d483bd
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20210224134948-620c54ef6199
)
