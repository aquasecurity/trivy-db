package utils

import (
	"time"

	"github.com/aquasecurity/trivy-db/pkg/log"
)

func MustTimeParse(value string) *time.Time {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		log.Error("Failed to parse time",
			log.String("value", value),
			log.Err(err))
		panic(err)
	}

	return &t
}
