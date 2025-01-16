package utils

import (
	"time"

	"github.com/briandowns/spinner"
	"github.com/cheggaaa/pb/v3"
)

var (
	Quiet = false
)

type Spinner struct {
	client *spinner.Spinner
}

func NewSpinner(suffix string) *Spinner {
	if Quiet {
		return &Spinner{}
	}
	s := spinner.New(spinner.CharSets[36], 100*time.Millisecond)
	s.Suffix = suffix
	return &Spinner{client: s}
}

func (s *Spinner) Start() {
	if s.client == nil {
		return
	}
	s.client.Start()
}
func (s *Spinner) Stop() {
	if s.client == nil {
		return
	}
	s.client.Stop()
}

// TODO: Expose an interface for progressbar
type ProgressBar struct {
	client *pb.ProgressBar
}

func NewProgressBar(total int) *ProgressBar {
	if Quiet {
		return &ProgressBar{}
	}
	bar := pb.StartNew(total)
	return &ProgressBar{client: bar}
}

func (p *ProgressBar) Increment() {
	if p.client == nil {
		return
	}
	p.client.Increment()
}
func (p *ProgressBar) Finish() {
	if p.client == nil {
		return
	}
	p.client.Finish()
}
