package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Global sink to prevent dead-code elimination.
var Sink int64

// Kernel 1: int loop sum
// Semantics: Tail recursion vs for-loop summing 1..10,000,000 using 64-bit int without overflow.
func intLoopSum() int64 {
	var sum int64
	for i := int64(1); i <= 10000000; i++ {
		sum += i
	}
	return sum
}

// Kernel 2: fib(27) recursive calls
// Semantics: Naive double recursion fib(27) = 196418, 635,621 recursive function calls.
func fib(n int64) int64 {
	if n < 2 {
		return n
	}
	return fib(n-1) + fib(n-2)
}

func fib27() int64 {
	return fib(27)
}

// Kernel 3: list build+map+fold 100k
// Semantics: Singly-linked list of boxed heap-allocated nodes (not a slice).
// Build 1..100k, map (+1) allocating new nodes, fold sum.
type ListNode struct {
	val  int64
	next *ListNode
}

func list100k() int64 {
	var head, tail *ListNode
	for i := int64(1); i <= 100000; i++ {
		node := &ListNode{val: i}
		if head == nil {
			head = node
			tail = node
		} else {
			tail.next = node
			tail = node
		}
	}
	var mapHead, mapTail *ListNode
	for curr := head; curr != nil; curr = curr.next {
		node := &ListNode{val: curr.val + 1}
		if mapHead == nil {
			mapHead = node
			mapTail = node
		} else {
			mapTail.next = node
			mapTail = node
		}
	}
	var sum int64
	for curr := mapHead; curr != nil; curr = curr.next {
		sum += curr.val
	}
	return sum
}

// Kernel 4: tuple setelement loop
// Semantics: 100k iterations of setelement(2, Tuple, I) replacing middle element
// of a 3-tuple and summing element(2, Next). Go copies a 3-element struct.
type Tuple3 struct {
	e1, e2, e3 int64
}

func tupleLoop() int64 {
	t := Tuple3{0, 0, 0}
	var sum int64
	for i := int64(100000); i > 0; i-- {
		next := Tuple3{t.e1, i, t.e3}
		sum += next.e2
		t = next
	}
	return sum
}

// Kernel 5: binary byte scan 1 MiB
// Semantics: Byte-by-byte scan of 1 MiB binary data with 4-byte repeating pattern,
// counting occurrences of byte value 2.
var binaryData []byte

func initBinary() {
	if len(binaryData) == 0 {
		binaryData = make([]byte, 1048576)
		pattern := []byte{1, 2, 3, 4}
		for i := range binaryData {
			binaryData[i] = pattern[i%4]
		}
	}
}

func binaryScan() int64 {
	var count int64
	for _, b := range binaryData {
		if b == 2 {
			count++
		}
	}
	return count
}

// Kernel 6: map put/get 100k small-int keys (Go map[int]int)
// Semantics: Insert 100k small-int keys (0..99999) with values I+1 into map[int]int,
// then lookup each key and sum retrieved values.
func mapPutGet() int64 {
	m := make(map[int]int)
	for i := 0; i < 100000; i++ {
		m[i] = i + 1
	}
	var sum int64
	for i := 0; i < 100000; i++ {
		sum += int64(m[i])
	}
	return sum
}

// Kernel 7: ETS-like hash table insert/lookup (Go map + sync.Mutex)
// Semantics: Hash table insert and lookup of 100k items. Protected by sync.Mutex.
type EtsTable struct {
	mu sync.Mutex
	m  map[int64]int64
}

func etsInsertLookup() int64 {
	tbl := &EtsTable{
		m: make(map[int64]int64),
	}
	for i := int64(0); i < 100000; i++ {
		tbl.mu.Lock()
		tbl.m[i] = i + 1
		tbl.mu.Unlock()
	}
	var sum int64
	for i := int64(0); i < 100000; i++ {
		tbl.mu.Lock()
		v := tbl.m[i]
		tbl.mu.Unlock()
		sum += v
	}
	return sum
}

// Kernel 8: process/goroutine spawn+exit 100k (with backlog)
// Semantics: Spawn 100k goroutines that send completion signal (1) and terminate;
// consumer receives all 100k only after all are spawned (accumulates buffered backlog).
func spawnExit() int64 {
	const n = 100000
	ch := make(chan int64, 1024)
	for i := 0; i < n; i++ {
		go func() {
			ch <- 1
		}()
	}
	var sum int64
	for i := 0; i < n; i++ {
		sum += <-ch
	}
	return sum
}

// Kernel 11: process/goroutine spawn+exit+recv 100k (no backlog)
// Semantics: Spawn 100k goroutines where parent receives each completion signal (1)
// immediately after each spawn (no backlog).
func spawnExitRecv() int64 {
	const n = 100000
	ch := make(chan int64, 1)
	var sum int64
	for i := 0; i < n; i++ {
		go func() {
			ch <- 1
		}()
		sum += <-ch
	}
	return sum
}

// Kernel 9: message ping-pong 1M (Go unbuffered channel)
// Semantics: 1,000,000 ping-pong round-trips over unbuffered channel between 2 goroutines.
func pingPong() int64 {
	const n = 1000000
	ping := make(chan struct{})
	pong := make(chan struct{})
	done := make(chan struct{})
	go func() {
		for range ping {
			pong <- struct{}{}
		}
		close(done)
	}()
	for i := 0; i < n; i++ {
		ping <- struct{}{}
		<-pong
	}
	close(ping)
	<-done
	return n
}

// Kernel 10: fan-in 8 producers
// Semantics: 8 concurrent producers each sending 125,000 messages (total 1,000,000)
// to a single consumer channel.
func fanIn() int64 {
	const producers = 8
	const perProd = 125000
	const total = producers * perProd
	ch := make(chan int64, 1024)
	for p := 0; p < producers; p++ {
		go func() {
			for i := 0; i < perProd; i++ {
				ch <- 1
			}
		}()
	}
	var sum int64
	for i := 0; i < total; i++ {
		sum += <-ch
	}
	return sum
}

// Kernel 12: float math 1M
// Semantics: 1M iterations of x = x*1.0000001 + 0.5 (boxed floats in Erlang; Go float64).
func floatMath() int64 {
	var x float64 = 0.0
	for i := 0; i < 1000000; i++ {
		x = x*1.0000001 + 0.5
	}
	return int64(x)
}

// Kernel 13: closure calls 1M
// Semantics: 1M calls of a captured fun F(X) -> X + K through lists:foldl vs Go closure in a loop.
func closureCalls() int64 {
	k := int64(10)
	f := func(x int64) int64 {
		return x + k
	}
	var sum int64
	for i := int64(1); i <= 1000000; i++ {
		sum += f(i)
	}
	return sum
}

// Kernel 14: binary build 1 MiB
// Semantics: build a 1 MiB binary by appending 1 byte at a time (<<Acc/binary, B>>, private_append) vs Go append to []byte.
func binaryBuild() int64 {
	buf := make([]byte, 0)
	for i := 1048576; i > 0; i-- {
		b := byte(i % 256)
		buf = append(buf, b)
	}
	return int64(len(buf))
}

// Kernel 15: record/tuple update 1M
// Semantics: 1M updates of a 5-field record (setelement semantics) vs Go struct copy.
type Rec5 struct {
	f1, f2, f3, f4, f5 int64
}

func recordTupleUpdate() int64 {
	rec := Rec5{0, 0, 0, 0, 0}
	var sum int64
	for i := int64(1000000); i > 0; i-- {
		next := Rec5{rec.f1, rec.f2, i, rec.f4, rec.f5}
		sum += next.f3
		rec = next
	}
	return sum
}

// Kernel 16: string→atom→string 100k
// Semantics: 100k list_to_atom/atom_to_list of existing atoms vs Go map[string]int interning.
var internMap map[string]int
var reverseTable []string
var strings100k []string

func initStringAtom() {
	if len(strings100k) == 0 {
		internMap = make(map[string]int, 1000)
		reverseTable = make([]string, 1000)
		pool := make([]string, 1000)
		for i := 0; i < 1000; i++ {
			s := "atom_" + strconv.Itoa(i)
			pool[i] = s
			internMap[s] = i
			reverseTable[i] = s
		}
		strings100k = make([]string, 0, 100000)
		for rep := 0; rep < 100; rep++ {
			strings100k = append(strings100k, pool...)
		}
	}
}

func stringAtomString() int64 {
	var sum int64
	for _, s := range strings100k {
		id := internMap[s]
		s2 := reverseTable[id]
		sum += int64(len(s2))
	}
	return sum
}

// Kernel 17: sort 100k ints
// Semantics: lists:sort of pseudo-random ints (fixed seed) vs Go sort.Ints on a copy.
var sortData []int

func initSort() {
	if len(sortData) == 0 {
		sortData = make([]int, 100000)
		for i := 1; i <= 100000; i++ {
			sortData[i-1] = int((int64(i)*1664525 + 1013904223) & 0x7FFFFFFF)
		}
	}
}

func sort100kInts() int64 {
	work := make([]int, len(sortData))
	copy(work, sortData)
	sort.Ints(work)
	return int64(work[0]) + int64(work[49999]) + int64(work[len(work)-1])
}

// Kernel 18: gen_server call 100k
// Semantics: 100k gen_server:call round-trips to a local server vs Go request/response over two unbuffered channels.
func genServerCall() int64 {
	const n = 100000
	req := make(chan int64)
	resp := make(chan int64)
	done := make(chan struct{})

	go func() {
		var state int64
		for val := range req {
			state += val
			resp <- state
		}
		close(done)
	}()

	var lastRes int64
	for i := 0; i < n; i++ {
		req <- 1
		lastRes = <-resp
	}
	close(req)
	<-done
	return lastRes
}

type KernelInfo struct {
	Name     string
	Expected int64
	OpCount  int64
	Fn       func() int64
}

var kernels = []KernelInfo{
	{"int_loop_sum", 50000005000000, 10000000, intLoopSum},
	{"fib_27", 196418, 635621, fib27},
	{"list_100k", 5000150000, 100000, list100k},
	{"tuple_loop", 5000050000, 100000, tupleLoop},
	{"binary_scan", 262144, 1048576, binaryScan},
	{"map_put_get", 5000050000, 100000, mapPutGet},
	{"ets_insert_lookup", 5000050000, 100000, etsInsertLookup},
	{"spawn_exit", 100000, 100000, spawnExit},
	{"spawn_exit_recv", 100000, 100000, spawnExitRecv},
	{"ping_pong", 1000000, 1000000, pingPong},
	{"fan_in", 1000000, 1000000, fanIn},
	{"float_math", 525854, 1000000, floatMath},
	{"closure_calls", 500010500000, 1000000, closureCalls},
	{"binary_build", 1048576, 1048576, binaryBuild},
	{"record_update", 500000500000, 1000000, recordTupleUpdate},
	{"string_atom_string", 789000, 100000, stringAtomString},
	{"sort_100k", 3227487306, 100000, sort100kInts},
	{"gen_server_call", 100000, 100000, genServerCall},
}

func main() {
	initBinary()
	initStringAtom()
	initSort()

	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <kernel_name> <warmup_count> <repeat_count>\n", os.Args[0])
		os.Exit(1)
	}

	kernelName := os.Args[1]
	warmup, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid warmup: %v\n", err)
		os.Exit(1)
	}
	repeats, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid repeats: %v\n", err)
		os.Exit(1)
	}

	var target *KernelInfo
	for i := range kernels {
		if kernels[i].Name == kernelName {
			target = &kernels[i]
			break
		}
	}
	if target == nil {
		fmt.Fprintf(os.Stderr, "unknown kernel: %s\n", kernelName)
		os.Exit(1)
	}

	// Warmup
	for i := 0; i < warmup; i++ {
		res := target.Fn()
		Sink += res
		if res != target.Expected {
			fmt.Printf("MISMATCH %s: got %d expected %d\n", target.Name, res, target.Expected)
			os.Exit(2)
		}
	}

	// Timed repeats
	var timesNs []int64
	var lastRes int64
	for i := 0; i < repeats; i++ {
		start := time.Now()
		res := target.Fn()
		elapsed := time.Since(start).Nanoseconds()
		Sink += res
		lastRes = res
		if res != target.Expected {
			fmt.Printf("MISMATCH %s: got %d expected %d\n", target.Name, res, target.Expected)
			os.Exit(2)
		}
		timesNs = append(timesNs, elapsed)
	}

	// Output format: {ok, Checksum, [TimeNs1, TimeNs2, ...]}
	fmt.Printf("{ok,%d,[", lastRes)
	for i, t := range timesNs {
		if i > 0 {
			fmt.Print(",")
		}
		fmt.Print(t)
	}
	fmt.Println("]}")
}
