package closer

import (
	"log"
	"os"
	"os/signal"
	"sync"
)

var globalCloser = New()

// Add func to global close list
func Add(f ...func() error) {
	globalCloser.Add(f...)
}

// Wait close all funcs of global closer
func Wait() {
	globalCloser.Wait()
}

// CloseAll funcs of global closer
func CloseAll() {
	globalCloser.CloseAll()
}

// Closer struct to manage shutdown
type Closer struct {
	mu    sync.Mutex
	once  sync.Once
	done  chan struct{}
	funcs []func() error
}

// New create Closer
func New(sig ...os.Signal) *Closer {
	c := &Closer{done: make(chan struct{})}

	if len(sig) > 0 {
		go func() {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, sig...)
			<-ch
			signal.Stop(ch)
			c.CloseAll()
		}()
	}

	return c
}

// Add func to close list
func (c *Closer) Add(f ...func() error) {
	c.mu.Lock()
	c.funcs = append(c.funcs, f...)
	c.mu.Unlock()
}

// Wait close all funcs of closer
func (c *Closer) Wait() {
	<-c.done
}

// CloseAll funcs of global closer
func (c *Closer) CloseAll() {
	c.once.Do(func() {
		defer close(c.done)

		c.mu.Lock()
		funcs := c.funcs
		c.funcs = nil
		c.mu.Unlock()

		errs := make(chan error, len(funcs))
		for _, f := range funcs {
			go func(f func() error) {
				errs <- f()
			}(f)
		}

		for range cap(errs) {
			if err := <-errs; err != nil {
				log.Printf("error returned from Closer: %v\n", err)
			}
		}
	})
}
