package finalmask

// The masks register themselves.
import (
	_ "github.com/metacubex/mihomo/transport/finalmask/fragment"
	_ "github.com/metacubex/mihomo/transport/finalmask/mkcplegacy"
	_ "github.com/metacubex/mihomo/transport/finalmask/noise"
	_ "github.com/metacubex/mihomo/transport/finalmask/realm"
	_ "github.com/metacubex/mihomo/transport/finalmask/salamander"
	_ "github.com/metacubex/mihomo/transport/finalmask/udphop"
	_ "github.com/metacubex/mihomo/transport/finalmask/xicmp"
	_ "github.com/metacubex/mihomo/transport/finalmask/xmc"
)
