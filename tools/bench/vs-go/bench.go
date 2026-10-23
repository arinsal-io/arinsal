package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

func fib(n int) int {
	if n < 2 {
		return n
	}
	return fib(n-1) + fib(n-2)
}

type node struct{ l, r *node }

func mk(d int) *node {
	if d == 0 {
		return &node{}
	}
	return &node{mk(d - 1), mk(d - 1)}
}
func check(n *node) int {
	if n.l == nil {
		return 1
	}
	return 1 + check(n.l) + check(n.r)
}
func trees(max int) int {
	sum := 0
	for d := 4; d <= max; d += 2 {
		for i := 0; i < 1<<(max-d+4); i++ {
			sum += check(mk(d))
		}
	}
	return sum
}

type body struct{ x, y, z, vx, vy, vz, m float64 }

func nbody(n int) float64 {
	b := []body{{0, 0, 0, 0, 0, 0, 39.47}, {4.84, -1.16, -0.10, 0.60, 2.81, -0.02, 0.037}, {8.34, 4.12, -0.4, -1.01, 1.82, 0.008, 0.011}, {12.89, -15.11, -0.22, 1.08, 0.86, -0.01, 0.0017}, {15.37, -25.9, 0.17, 0.97, 0.59, -0.03, 0.002}}
	for s := 0; s < n; s++ {
		for i := range b {
			for j := i + 1; j < len(b); j++ {
				dx, dy, dz := b[i].x-b[j].x, b[i].y-b[j].y, b[i].z-b[j].z
				d2 := dx*dx + dy*dy + dz*dz
				mag := 0.01 / (d2 * math.Sqrt(d2))
				b[i].vx -= dx * b[j].m * mag
				b[i].vy -= dy * b[j].m * mag
				b[i].vz -= dz * b[j].m * mag
				b[j].vx += dx * b[i].m * mag
				b[j].vy += dy * b[i].m * mag
				b[j].vz += dz * b[i].m * mag
			}
		}
		for i := range b {
			b[i].x += 0.01 * b[i].vx
			b[i].y += 0.01 * b[i].vy
			b[i].z += 0.01 * b[i].vz
		}
	}
	return b[0].x
}
func tasks(n int) int {
	var wg sync.WaitGroup
	release := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-release }()
	}
	close(release)
	wg.Wait()
	return n
}
func ring(n, m int) int {
	channels := make([]chan int, n)
	for i := range channels {
		channels[i] = make(chan int, 1)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := range channels {
		next := channels[(i+1)%n]
		mine := channels[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for v := range mine {
				if v == 0 {
					return
				}
				if v == 1 {
					done <- struct{}{}
				} else {
					next <- v - 1
				}
			}
		}()
	}
	channels[0] <- m
	<-done
	for _, ch := range channels {
		close(ch)
	}
	wg.Wait()
	return m
}
func pingpong(n int) int {
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
func bigmsg(n int) int {
	binaryData := make([]byte, 1048576)
	for i := range binaryData {
		binaryData[i] = 7
	}
	list := make([]uint64, 65536)
	for i := range list {
		list[i] = 7
	}
	messages := make(chan any)
	acks := make(chan int)
	done := make(chan struct{})
	go func() {
		for v := range messages {
			switch x := v.(type) {
			case []byte:
				acks <- len(x)
			case []uint64:
				sum := 0
				for _, value := range x {
					sum += int(value)
				}
				acks <- sum
			}
		}
		close(done)
	}()
	for i := 0; i < n; i++ {
		messages <- binaryData
		<-acks
		messages <- append([]uint64(nil), list...)
		<-acks
	}
	close(messages)
	<-done
	return n * (1048576 + 458752)
}
func mapUpdate(n, size int) int {
	m := make(map[int]int, size)
	for i := 0; i < size; i++ {
		m[i] = 0
	}
	for i := 0; i < n; i++ {
		m[i%size] = i + 1
	}
	return len(m) + m[(n-1)%size]
}
func binaryParse(mb int) int {
	frame := make([]byte, 1028)
	binary.BigEndian.PutUint32(frame[:4], 1024)
	frame[4] = 7
	frame[len(frame)-1] = 9
	stream := make([]byte, len(frame)*mb*1024)
	for i := 0; i < len(stream); i += len(frame) {
		copy(stream[i:], frame)
	}
	sum := 0
	for len(stream) > 0 {
		length := int(binary.BigEndian.Uint32(stream[:4]))
		payload := stream[4 : 4+length]
		sum += length
		for _, value := range payload {
			sum += int(value)
		}
		stream = stream[4+length:]
	}
	return sum
}
func ets(n int) int {
	var table sync.Map
	for i := 0; i < 1000; i++ {
		table.Store(i, 0)
	}
	var wg sync.WaitGroup
	sums := make(chan int, 4)
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			local := 0
			for i := 0; i < n/4; i++ {
				key := (i*4 + w) % 1000
				if i%4 == 0 {
					table.Store(key, i)
				} else {
					if _, ok := table.Load(key); !ok {
						panic("missing key")
					}
				}
				local++
			}
			sums <- local
		}(worker)
	}
	wg.Wait()
	close(sums)
	total := 0
	for v := range sums {
		total += v
	}
	return total
}
func fanin(n int) int {
	messages := make(chan int, 1024)
	var wg sync.WaitGroup
	for p := 0; p < 1000; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n/1000; i++ {
				messages <- 1
			}
		}()
	}
	go func() { wg.Wait(); close(messages) }()
	sum := 0
	for v := range messages {
		sum += v
	}
	return sum
}
func fanout(n int) int {
	channels := make([]chan int, 1000)
	done := make(chan int, 1000)
	for i := range channels {
		ch := make(chan int, 1)
		channels[i] = ch
		go func() {
			sum := 0
			for v := range ch {
				sum += v
			}
			done <- sum
		}()
	}
	for i := 0; i < n/1000; i++ {
		for _, ch := range channels {
			ch <- 1
		}
	}
	for _, ch := range channels {
		close(ch)
	}
	sum := 0
	for range channels {
		sum += <-done
	}
	return sum
}
func forward(n int) int {
	list := make([]uint64, 65536)
	for i := range list {
		list[i] = 7
	}
	chans := make([]chan []uint64, 10)
	for i := range chans {
		chans[i] = make(chan []uint64)
	}
	acks := make(chan uint64)
	for i := 0; i < 9; i++ {
		go func(in, out chan []uint64) {
			for v := range in {
				out <- v
			}
			close(out)
		}(chans[i], chans[i+1])
	}
	go func() {
		for v := range chans[9] {
			var sum uint64
			for _, x := range v {
				sum += x
			}
			acks <- sum
		}
	}()
	for i := 0; i < n; i++ {
		chans[0] <- list
		if <-acks != 458752 {
			panic("forward ack")
		}
	}
	close(chans[0])
	return n * 458752
}

func broadcast(n int) int {
	list := make([]uint64, 65536)
	for i := range list {
		list[i] = 7
	}
	const receivers = 1000
	ins := make([]chan []uint64, receivers)
	acks := make(chan uint64, receivers)
	for i := range ins {
		ins[i] = make(chan []uint64, 1)
		go func(in chan []uint64) {
			for v := range in {
				acks <- v[0]
			}
		}(ins[i])
	}
	for r := 0; r < n; r++ {
		for _, in := range ins {
			in <- list
		}
		for k := 0; k < receivers; k++ {
			if <-acks != 7 {
				panic("broadcast ack")
			}
		}
	}
	for _, in := range ins {
		close(in)
	}
	return n * receivers * 7
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: bench NAME N [M]")
		os.Exit(2)
	}
	name := os.Args[1]
	n, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	runtime.GOMAXPROCS(4)
	start := time.Now()
	var result any
	switch name {
	case "fib":
		result = fib(n)
	case "trees":
		result = trees(n)
	case "nbody":
		result = nbody(n)
	case "idle":
		result = 0
	case "tasks":
		result = tasks(n)
	case "ring":
		m, _ := strconv.Atoi(os.Args[3])
		result = ring(n, m)
	case "pingpong":
		result = pingpong(n)
	case "bigmsg":
		result = bigmsg(n)
	case "map_update":
		result = mapUpdate(n, 1000)
	case "map_update_small":
		result = mapUpdate(n, 32)
	case "binary_parse":
		result = binaryParse(n)
	case "ets":
		result = ets(n)
	case "fanin":
		result = fanin(n)
	case "fanout":
		result = fanout(n)
	case "forward":
		result = forward(n)
	case "broadcast":
		result = broadcast(n)
	default:
		panic("unknown benchmark")
	}
	elapsedMs := float64(time.Since(start).Microseconds()) / 1000
	fmt.Println(result)
	fmt.Printf("%s %.3fms\n", name, elapsedMs)
}
