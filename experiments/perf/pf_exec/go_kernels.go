package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"time"
)

func fib(n int64) int64 {
	if n < 2 {
		return n
	}
	return fib(n-1) + fib(n-2)
}

func run(name string, n int64) int64 {
	switch name {
	case "tail":
		var sum int64
		for i := n; i > 0; i-- {
			sum++
		}
		return sum
	case "list":
		input := make([]int64, n)
		for i := range input {
			input[i] = int64(i) + 1
		}
		mapped := make([]int64, n)
		for i, x := range input {
			mapped[i] = x + 1
		}
		var sum int64
		for _, x := range mapped {
			sum += x
		}
		return sum
	case "fib":
		return fib(n)
	case "tuple":
		tuple := [3]int64{}
		var sum int64
		for i := n; i > 0; i-- {
			next := tuple
			next[1] = i
			sum += next[1]
			tuple = next
		}
		return sum
	case "binary":
		data := bytes.Repeat([]byte{1, 2, 3, 4}, int(n))
		var sum int64
		for _, x := range data {
			if x == 2 {
				sum++
			}
		}
		return sum
	default:
		panic(name)
	}
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: go_kernels NAME N")
	}
	n, err := strconv.ParseInt(os.Args[2], 10, 64)
	if err != nil {
		panic(err)
	}
	start := time.Now()
	value := run(os.Args[1], n)
	fmt.Printf("%d %.0f\n", value, float64(time.Since(start).Nanoseconds()))
}
