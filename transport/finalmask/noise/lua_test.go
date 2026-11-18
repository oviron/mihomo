package noise

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// writeScript puts a Lua file into a fresh home directory and returns its name.
func writeScript(t *testing.T, code string) string {
	t.Helper()
	home := C.Path.HomeDir()
	dir := t.TempDir()
	C.SetHomeDir(dir)
	t.Cleanup(func() { C.SetHomeDir(home) })
	require.NoError(t, os.WriteFile(filepath.Join(dir, "noise.lua"), []byte(code), 0o600))
	return "noise.lua"
}

func scriptPackets(t *testing.T, code string) ([]scriptPacket, error) {
	t.Helper()
	m, err := New(map[string]any{"script": writeScript(t, code)})
	require.NoError(t, err)
	return m.script.packets("192.0.2.1:443")
}

func TestScriptBuildsNoise(t *testing.T) {
	packets, err := scriptPackets(t, `
local noise = require("xray.finalmask.noise")
local log = require("xray.log")
local calls = 0

function HandleNoise(plan, address)
	calls = calls + 1
	log.Debug("noise for ", address, " call ", calls)
	plan:Add("to " .. address)
	plan:Add(string.char(0xc0, 0x00) .. noise.Random(10), 5)
	plan:AddRandom(noise.RandomBetween(20, 30), 0)
	plan:Add(string.format("%d", calls))
end
`)
	require.NoError(t, err)
	require.Len(t, packets, 4)
	require.Equal(t, "to 192.0.2.1:443", string(packets[0].packet))
	require.Len(t, packets[1].packet, 12)
	require.Equal(t, []byte{0xc0, 0x00}, packets[1].packet[:2])
	require.Equal(t, 5*time.Millisecond, packets[1].delay)
	require.GreaterOrEqual(t, len(packets[2].packet), 20)
	require.LessOrEqual(t, len(packets[2].packet), 30)
	require.Equal(t, "1", string(packets[3].packet))
}

// The mask sends what the script planned ahead of the first packet, and the
// script keeps its state between calls.
func TestScriptConn(t *testing.T) {
	sender, receiver := newConn(t, map[string]any{"reset": 1, "script": writeScript(t, `
local calls = 0
function HandleNoise(plan, address)
	calls = calls + 1
	plan:Add("noise " .. calls)
	plan:Add("more", 20)
end
`)})
	write := func() {
		_, err := sender.WriteTo([]byte("data"), receiver.LocalAddr())
		require.NoError(t, err)
	}
	write()
	write()
	packets := drain(t, receiver)
	require.Len(t, packets, 4)
	require.Equal(t, "noise 1", string(packets[0]))
	require.Equal(t, "more", string(packets[1]))
	require.Equal(t, "data", string(packets[2]))

	time.Sleep(1200 * time.Millisecond)
	write()
	packets = drain(t, receiver)
	require.Len(t, packets, 3)
	require.Equal(t, "noise 2", string(packets[0]))
}

func TestScriptReportsAndLimits(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"returned string":  {`return "not now"`, "not now"},
		"runtime error":    {`error("boom")`, "boom"},
		"bad return":       {`return 42`, "must return"},
		"too many packets": {`for i = 1, 65 do plan:Add("x") end`, "at most 64 packets"},
		"too many bytes":   {`plan:AddRandom(40000) plan:AddRandom(40000)`, "at most 65535 bytes"},
		"packet too large": {`plan:AddRandom(70000)`, "size of 0 to 65535"},
		"bad packet":       {`plan:Add(42)`, "packet string"},
		"bad delay":        {`plan:Add("x", -1)`, "delay"},
		"endless loop":     {`while true do end`, "context deadline exceeded"},
	} {
		t.Run(name, func(t *testing.T) {
			packets, err := scriptPackets(t, "function HandleNoise(plan, address)\n"+tc.body+"\nend")
			require.ErrorContains(t, err, tc.want)
			require.Empty(t, packets)
		})
	}

	// after a failed call the script works again, from a fresh state
	m, err := New(map[string]any{"script": writeScript(t, `
local calls = 0
function HandleNoise(plan, address)
	calls = calls + 1
	if address == "bad" then error("no noise for this one") end
	plan:Add("call " .. calls)
end
`)})
	require.NoError(t, err)
	packets, err := m.script.packets("good")
	require.NoError(t, err)
	require.Equal(t, "call 1", string(packets[0].packet))
	_, err = m.script.packets("bad")
	require.Error(t, err)
	packets, err = m.script.packets("good")
	require.NoError(t, err)
	require.Equal(t, "call 1", string(packets[0].packet), "the state was made again")
}

// The plan can't be kept and filled outside HandleNoise.
func TestScriptPlanIsClosedOutsideTheCall(t *testing.T) {
	m, err := New(map[string]any{"script": writeScript(t, `
local kept
function HandleNoise(plan, address)
	if kept then kept:Add("late") end
	kept = plan
	plan:Add("x")
end
`)})
	require.NoError(t, err)
	packets, err := m.script.packets("a")
	require.NoError(t, err)
	require.Len(t, packets, 1)
	packets, err = m.script.packets("a")
	require.NoError(t, err)
	require.Len(t, packets, 2) // the same plan object, open again during the call
}

func TestScriptSandbox(t *testing.T) {
	for name, expr := range map[string]string{
		"io":           `io`,
		"os.execute":   `os.execute`,
		"os.getenv":    `os.getenv`,
		"os.remove":    `os.remove`,
		"dofile":       `dofile`,
		"loadstring":   `loadstring`,
		"load":         `load`,
		"setmetatable": `setmetatable`,
		"rawset":       `rawset`,
		"debug":        `debug`,
		"package":      `package`,
		"string.dump":  `string.dump`,
		"randomseed":   `math.randomseed`,
		"print":        `print`,
	} {
		packets, err := scriptPackets(t, "function HandleNoise(plan, address)\nplan:Add(tostring("+expr+" == nil))\nend")
		require.NoError(t, err, name)
		require.Equal(t, "true", string(packets[0].packet), name)
	}

	// what stays: the clock, strings, math, tables, pcall, the preloaded modules
	packets, err := scriptPackets(t, `
function HandleNoise(plan, address)
	local ok, err = pcall(require, "socket")
	plan:Add(tostring(ok))
	plan:Add(tostring(os.time() > 0) .. tostring(math.floor(2.5)) .. table.concat({"a", "b"}))
	plan:Add(tostring({}) .. string.format("%s", function() end))
end
`)
	require.NoError(t, err)
	require.Equal(t, "false", string(packets[0].packet))
	require.Equal(t, "true2ab", string(packets[1].packet))
	require.Equal(t, "<opaque><opaque>", string(packets[2].packet), "no memory addresses")
}

// The pattern functions work on inputs of a sane size and refuse the rest.
func TestScriptPatternFunctions(t *testing.T) {
	packets, err := scriptPackets(t, `
function HandleNoise(plan, address)
	local host, port = string.match(address, "^(.*):(%d+)$")
	plan:Add(host .. "|" .. port)
	plan:Add((string.gsub("a-b-c", "-", "+")))
	plan:Add(tostring(string.find("hello", "l+")))
	local words = {}
	for word in string.gmatch("one two", "%a+") do words[#words + 1] = word end
	plan:Add(table.concat(words, ","))
	plan:Add(tostring(("x"):rep(20000):find("y", 1, true) == nil)) -- methods go the same way
end
`)
	require.ErrorContains(t, err, "at most 16384 bytes")
	require.Empty(t, packets)

	packets, err = scriptPackets(t, `
function HandleNoise(plan, address)
	local host, port = string.match(address, "^(.*):(%d+)$")
	plan:Add(host .. "|" .. port)
	plan:Add((string.gsub("a-b-c", "-", "+")))
	plan:Add(tostring(string.find("hello", "l+")))
	local words = {}
	for word in string.gmatch("one two", "%a+") do words[#words + 1] = word end
	plan:Add(table.concat(words, ","))
end
`)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1|443", string(packets[0].packet))
	require.Equal(t, "a+b+c", string(packets[1].packet))
	require.Equal(t, "3", string(packets[2].packet))
	require.Equal(t, "one,two", string(packets[3].packet))

	for name, call := range map[string]string{
		"long subject": `string.find(string.rep("a", 20000), "a*b")`,
		"long pattern": `string.match("a", string.rep("a?", 200))`,
		"gsub":         `string.gsub(string.rep("a", 20000), "a", "b")`,
		"gmatch":       `string.gmatch(string.rep("a", 20000), "a")`,
	} {
		_, err := scriptPackets(t, "function HandleNoise(plan, address)\n"+call+"\nend")
		require.ErrorContains(t, err, "at most", name)
	}
}

func TestScriptSettings(t *testing.T) {
	_, err := New(map[string]any{"script": writeScript(t, `function HandleNoise(plan) end`)})
	require.NoError(t, err)

	for name, code := range map[string]string{
		"no hook":      `local x = 1`,
		"syntax error": `function HandleNoise(`,
		"top level":    `error("at load")`,
	} {
		_, err := New(map[string]any{"script": writeScript(t, code)})
		require.Error(t, err, name)
	}

	_, err = New(map[string]any{"script": "missing.lua"})
	require.Error(t, err)
	_, err = New(map[string]any{"script": "noise.txt"})
	require.ErrorContains(t, err, ".lua")
	if !strings.Contains(os.Getenv("SAFE_PATHS"), "/") {
		_, err = New(map[string]any{"script": "/etc/outside-of-home.lua"})
		require.ErrorContains(t, err, "not subpath")
	}
}
