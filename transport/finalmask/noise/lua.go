package noise

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/finalmask/mask"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// The script of a noise mask is a Lua 5.1 program that defines
//
//	function HandleNoise(plan, address)
//
// It is called when noise is due for an address and adds the datagrams to
// send with plan:Add(packet [, delay_ms]) and plan:AddRandom(size [, delay_ms]).
// Returning a string, or an error value, sends nothing. The module
// xray.finalmask.noise gives Random(size) and RandomBetween(from, to), the
// module xray.log gives Debug, Info, Warning and Error. The script runs in a
// sandbox, as in Xray-core: no io, no os beyond the clock, no loading of code.
const (
	scriptValueLimit   = 65535 // bytes of noise per call, bytes of a packet, milliseconds of a delay
	scriptPacketLimit  = 64    // packets per call
	scriptCallTimeout  = time.Second
	scriptInitTimeout  = 120 * time.Second
	scriptRetryTimeout = 2 * time.Second // to load the program again after a failed call
	// The pattern functions of the Lua module match by recursion without a
	// limit on its depth, which an input long enough turns into a crash of
	// the process, and they don't notice the timeout. Their input is capped.
	scriptPatternSubjectLimit = 16 * 1024
	scriptPatternLimit        = 256
	// scriptRepLimit bounds the result of string.rep.
	scriptRepLimit     = 1 << 20
	scriptRegistrySize = 256
	scriptPlanKey      = "finalmask.noise.plan"
)

func init() {
	loadScript = newScript
}

// script runs HandleNoise of one program. Noise is rare, one Lua state behind
// a lock is enough.
type script struct {
	name  string
	proto *lua.FunctionProto

	mu    sync.Mutex
	state *lua.LState // nil after a failed call, made again for the next one
}

// scriptPlan collects what HandleNoise adds.
type scriptPlan struct {
	packets []scriptPacket
	bytes   int
	open    bool
}

func newScript(path string) (scriptSource, error) {
	if !strings.EqualFold(filepath.Ext(path), ".lua") {
		return nil, errors.New("the script file must have the .lua extension")
	}
	if !C.Path.IsSafePath(path) {
		return nil, C.Path.ErrNotSafePath(path)
	}
	path = C.Path.Resolve(path)
	code, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	chunk, err := parse.Parse(bytes.NewReader(code), path)
	if err != nil {
		return nil, err
	}
	proto, err := lua.Compile(chunk, path)
	if err != nil {
		return nil, err
	}
	s := &script{name: filepath.Base(path), proto: proto}
	if s.state, err = s.newState(scriptInitTimeout); err != nil {
		return nil, err
	}
	return s, nil
}

// newState runs the program's top level in a fresh sandbox.
func (s *script) newState(timeout time.Duration) (*lua.LState, error) {
	L := newSandbox(lua.Options{
		RegistrySize:     scriptRegistrySize,
		RegistryMaxSize:  lua.RegistrySize,
		RegistryGrowStep: scriptRegistrySize,
	})
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	L.SetContext(ctx)
	defer L.RemoveContext()

	s.registerModules(L)
	L.SetGlobal(lua.LoadLibName, lua.LNil) // the package table stays out of reach
	L.Push(L.NewFunctionFromProto(s.proto))
	if err := L.PCall(0, 0, nil); err != nil {
		L.Close()
		return nil, err
	}
	if L.GetGlobal("HandleNoise").Type() != lua.LTFunction {
		L.Close()
		return nil, errors.New("the noise script must define HandleNoise(plan, address)")
	}
	return L, nil
}

func (s *script) registerModules(L *lua.LState) {
	L.PreloadModule("xray.finalmask.noise", func(L *lua.LState) int {
		module := L.CreateTable(0, 2)
		module.RawSetString("Random", L.NewFunction(func(L *lua.LState) int {
			size := L.CheckNumber(1)
			if !(size >= 0 && size <= scriptValueLimit) {
				L.RaiseError("noise.Random requires a size of 0 to %d", scriptValueLimit)
				return 0
			}
			buf := make([]byte, int(size))
			_, _ = rand.Read(buf)
			L.Push(lua.LString(buf))
			return 1
		}))
		module.RawSetString("RandomBetween", L.NewFunction(func(L *lua.LState) int {
			from, to := L.CheckNumber(1), L.CheckNumber(2)
			if !(from >= 0 && from <= to && to <= scriptValueLimit) {
				L.RaiseError("noise.RandomBetween requires 0 <= from <= to <= %d", scriptValueLimit)
				return 0
			}
			L.Push(lua.LNumber(mask.RandBetween(int64(from), int64(to)+1)))
			return 1
		}))
		L.Push(module)
		return 1
	})

	L.PreloadModule("xray.log", func(L *lua.LState) int {
		module := L.CreateTable(0, 4)
		for name, level := range map[string]log.LogLevel{
			"Debug": log.DEBUG, "Info": log.INFO, "Warning": log.WARNING, "Error": log.ERROR,
		} {
			level := level
			module.RawSetString(name, L.NewFunction(func(L *lua.LState) int {
				if log.Level() > level {
					return 0
				}
				var content strings.Builder
				for i := 1; i <= L.GetTop(); i++ {
					content.WriteString(logString(L, L.Get(i)))
				}
				switch level {
				case log.DEBUG:
					log.Debugln("[finalmask] %s: %s", s.name, content.String())
				case log.INFO:
					log.Infoln("[finalmask] %s: %s", s.name, content.String())
				case log.WARNING:
					log.Warnln("[finalmask] %s: %s", s.name, content.String())
				default:
					log.Errorln("[finalmask] %s: %s", s.name, content.String())
				}
				return 0
			}))
		}
		L.Push(module)
		return 1
	})

	meta := L.CreateTable(0, 3)
	meta.RawSetString("__index", meta)
	meta.RawSetString("Add", L.NewFunction(planAdd))
	meta.RawSetString("AddRandom", L.NewFunction(planAddRandom))
	data := L.NewUserData()
	data.Value = &scriptPlan{}
	data.Metatable = meta
	L.SetField(L.Get(lua.RegistryIndex), scriptPlanKey, data)
}

func logString(L *lua.LState, value lua.LValue) string {
	if data, ok := value.(*lua.LUserData); ok {
		if err, ok := data.Value.(error); ok {
			return err.Error()
		}
	}
	if _, ok := L.GetMetaField(value, "__tostring").(*lua.LFunction); ok {
		return L.ToStringMeta(value).String()
	}
	return value.String()
}

func planAdd(L *lua.LState) int {
	packet, ok := L.Get(2).(lua.LString)
	if !ok {
		L.RaiseError("Add requires a packet string")
		return 0
	}
	plan := planFor(L, len(packet))
	plan.packets = append(plan.packets, scriptPacket{packet: []byte(packet), delay: planDelay(L, 3)})
	plan.bytes += len(packet)
	return 0
}

func planAddRandom(L *lua.LState) int {
	size := L.CheckNumber(2)
	if !(size >= 0 && size <= scriptValueLimit) {
		L.RaiseError("AddRandom requires a size of 0 to %d", scriptValueLimit)
		return 0
	}
	plan := planFor(L, int(size))
	packet := make([]byte, int(size))
	_, _ = rand.Read(packet)
	plan.packets = append(plan.packets, scriptPacket{packet: packet, delay: planDelay(L, 3)})
	plan.bytes += int(size)
	return 0
}

// planFor returns the plan the method was called on, if it may take size more bytes.
func planFor(L *lua.LState, size int) *scriptPlan {
	var plan *scriptPlan
	if data, ok := L.Get(1).(*lua.LUserData); ok {
		plan, _ = data.Value.(*scriptPlan)
	}
	switch {
	case plan == nil:
		L.RaiseError("the plan HandleNoise was given is missing")
	case !plan.open:
		L.RaiseError("the plan only takes packets while HandleNoise runs")
	case len(plan.packets) >= scriptPacketLimit:
		L.RaiseError("the plan takes at most %d packets per call", scriptPacketLimit)
	case plan.bytes+size > scriptValueLimit:
		L.RaiseError("the plan takes at most %d bytes of noise per call", scriptValueLimit)
	}
	return plan
}

func planDelay(L *lua.LState, index int) time.Duration {
	switch value := L.Get(index).(type) {
	case *lua.LNilType:
		return 0
	case lua.LNumber:
		if !(value >= 0 && value <= scriptValueLimit) {
			L.RaiseError("the delay must be 0 to %d milliseconds", scriptValueLimit)
			return 0
		}
		return time.Duration(value) * time.Millisecond
	default:
		L.RaiseError("the delay must be a number of milliseconds")
		return 0
	}
}

// packets calls HandleNoise for an address.
func (s *script) packets(addr string) ([]scriptPacket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		// the lock is held: every connection of the mask waits for this
		state, err := s.newState(scriptRetryTimeout)
		if err != nil {
			return nil, err
		}
		s.state = state
	}
	L := s.state
	data, _ := L.GetField(L.Get(lua.RegistryIndex), scriptPlanKey).(*lua.LUserData)
	if data == nil {
		return nil, errors.New("the noise script has no plan")
	}
	plan := data.Value.(*scriptPlan)
	plan.packets, plan.bytes, plan.open = nil, 0, true
	defer func() { plan.packets, plan.open = nil, false }()

	ctx, cancel := context.WithTimeout(context.Background(), scriptCallTimeout)
	defer cancel()
	L.SetContext(ctx)
	defer L.RemoveContext()
	if err := L.CallByParam(lua.P{Fn: L.GetGlobal("HandleNoise"), NRet: 1, Protect: true}, data, lua.LString(addr)); err != nil {
		// a state that was interrupted is not used again
		L.Close()
		s.state = nil
		return nil, err
	}
	result := L.Get(-1)
	L.Pop(1)
	switch value := result.(type) {
	case *lua.LNilType:
		return plan.packets, nil
	case lua.LString:
		return nil, errors.New(string(value))
	case *lua.LUserData:
		if err, ok := value.Value.(error); ok {
			return nil, err
		}
	}
	return nil, errors.New("the noise script must return nothing, an error or a string")
}

// newSandbox is a Lua state with the base, table, string and math libraries
// and the clock functions of os, without anything that loads code, reaches
// the system or shows memory addresses.
func newSandbox(options lua.Options) *lua.LState {
	options.SkipOpenLibs = true
	L := lua.NewState(options)

	for _, lib := range []struct {
		name string
		open lua.LGFunction
	}{
		{lua.LoadLibName, lua.OpenPackage},
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
		{lua.OsLibName, lua.OpenOs},
	} {
		L.Push(L.NewFunction(lib.open))
		L.Push(lua.LString(lib.name))
		L.Call(1, 0)
	}

	for _, name := range []string{
		"dofile", "loadfile", "load", "loadstring", "getfenv", "setfenv",
		"getmetatable", "setmetatable", "rawget", "rawset",
		"collectgarbage", "module", "newproxy", "print", "_printregs",
	} {
		L.SetGlobal(name, lua.LNil)
	}

	// tostring and string.format would print the addresses of tables and functions.
	toString := func(value lua.LValue) lua.LString {
		result := "<opaque>"
		switch value.Type() {
		case lua.LTNil, lua.LTBool, lua.LTNumber, lua.LTString:
			result = value.String()
		case lua.LTUserData:
			switch native := value.(*lua.LUserData).Value.(type) {
			case error:
				result = redactAddresses(native.Error())
			case fmt.Stringer:
				result = native.String()
			}
		}
		return lua.LString(result)
	}
	L.SetGlobal("tostring", L.NewFunction(func(L *lua.LState) int {
		L.Push(toString(L.CheckAny(1)))
		return 1
	}))
	stringLib := L.GetGlobal(lua.StringLibName).(*lua.LTable)
	stringLib.RawSetString("dump", lua.LNil)
	for _, name := range []string{"find", "match", "gmatch", "gsub"} {
		name := name
		match := stringLib.RawGetString(name)
		stringLib.RawSetString(name, L.NewFunction(func(L *lua.LState) int {
			if len(L.CheckString(1)) > scriptPatternSubjectLimit || len(L.CheckString(2)) > scriptPatternLimit {
				L.RaiseError("string.%s takes a string of at most %d bytes and a pattern of at most %d", name, scriptPatternSubjectLimit, scriptPatternLimit)
				return 0
			}
			nargs := L.GetTop()
			L.Insert(match, 1)
			L.Call(nargs, lua.MultRet)
			return L.GetTop()
		}))
	}
	// string.rep builds its result in one allocation, past the instruction
	// counting that stops a script
	rep := stringLib.RawGetString("rep")
	stringLib.RawSetString("rep", L.NewFunction(func(L *lua.LState) int {
		if n := L.CheckInt(2); n > 0 && len(L.CheckString(1)) > scriptRepLimit/n {
			L.RaiseError("string.rep makes a string of at most %d bytes", scriptRepLimit)
			return 0
		}
		nargs := L.GetTop()
		L.Insert(rep, 1)
		L.Call(nargs, lua.MultRet)
		return L.GetTop()
	}))
	format := stringLib.RawGetString("format")
	stringLib.RawSetString("format", L.NewFunction(func(L *lua.LState) int {
		nargs := L.GetTop()
		for i := 2; i <= nargs; i++ {
			value := L.Get(i)
			switch value.Type() {
			case lua.LTBool, lua.LTNumber, lua.LTString:
				continue
			}
			L.Replace(i, toString(value))
		}
		L.Insert(format, 1)
		L.Call(nargs, 1)
		return 1
	}))

	// So would the messages of caught errors.
	redactError := func(value lua.LValue) lua.LValue {
		if message, ok := value.(lua.LString); ok {
			return lua.LString(redactAddresses(string(message)))
		}
		return value
	}
	for _, name := range []string{"pcall", "xpcall"} {
		name := name
		call := L.GetGlobal(name)
		L.SetGlobal(name, L.NewFunction(func(L *lua.LState) int {
			nargs := L.GetTop()
			if name == "xpcall" {
				L.CheckFunction(1)
				handler := L.CheckFunction(2)
				L.Replace(2, L.NewFunction(func(L *lua.LState) int {
					L.Replace(1, redactError(L.Get(1)))
					L.Insert(handler, 1)
					L.Call(1, 1)
					return 1
				}))
			}
			L.Insert(call, 1)
			L.Call(nargs, lua.MultRet)
			if L.Get(1) == lua.LFalse {
				L.Replace(2, redactError(L.Get(2)))
			}
			return L.GetTop()
		}))
	}

	L.GetGlobal(lua.MathLibName).(*lua.LTable).RawSetString("randomseed", lua.LNil)

	osLib := L.GetGlobal(lua.OsLibName).(*lua.LTable)
	var drop []lua.LValue
	osLib.ForEach(func(key, _ lua.LValue) {
		switch key {
		case lua.LString("clock"), lua.LString("date"), lua.LString("difftime"), lua.LString("time"):
		default:
			drop = append(drop, key)
		}
	})
	for _, key := range drop {
		osLib.RawSet(key, lua.LNil)
	}

	// require finds the preloaded modules only.
	pkg := L.GetGlobal(lua.LoadLibName).(*lua.LTable)
	preload := pkg.RawGetString("preload").(*lua.LTable)
	loaders := L.CreateTable(1, 0)
	loaders.RawSetInt(1, L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		loader := preload.RawGetString(name)
		if loader == lua.LNil {
			loader = lua.LString("no preloaded module: " + name)
		}
		L.Push(loader)
		return 1
	}))
	pkg.RawSetString("loaders", loaders)
	L.SetField(L.Get(lua.RegistryIndex), "_LOADERS", loaders)
	for _, name := range []string{"loadlib", "seeall", "path", "cpath", "config"} {
		pkg.RawSetString(name, lua.LNil)
	}
	return L
}

var addressPattern = regexp.MustCompile(`0[xX][0-9a-fA-F]+`)

func redactAddresses(message string) string {
	return addressPattern.ReplaceAllString(message, "<address>")
}
