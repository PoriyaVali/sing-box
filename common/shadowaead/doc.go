// Package shadowaead is github.com/sagernet/sing-shadowsocks/shadowaead at
// v0.2.8, copied here to fix MultiService, which the multi-user shadowsocks
// inbound uses. See service_multi.go: the user map was emptied and refilled
// in place while connections iterated it.
//
// Only MultiService changed. Everything else is upstream's code as it was,
// under upstream's license:
//
// Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
package shadowaead
