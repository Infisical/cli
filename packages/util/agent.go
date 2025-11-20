package util

import (
	"fmt"
	"strconv"
	"time"
)

// ParseTimeDurationString converts a string representation of a polling interval to a time.Duration
func ParseTimeDurationString(pollingInterval string, allowLessThanOneSecond bool) (time.Duration, error) {
	length := len(pollingInterval)
	if length < 2 {
		return 0, fmt.Errorf("invalid format")
	}

	splitIndex := length
	for i := length - 1; i >= 0; i-- {
		if pollingInterval[i] >= '0' && pollingInterval[i] <= '9' {
			splitIndex = i + 1
			break
		}
	}

	if splitIndex == 0 || splitIndex == length {
		return 0, fmt.Errorf("invalid format: must contain both number and unit")
	}

	numberPart := pollingInterval[:splitIndex]
	unit := pollingInterval[splitIndex:]

	number, err := strconv.Atoi(numberPart)
	if err != nil {
		return 0, err
	}

	switch unit {
	case "s":
		if number < 60 && !IsDevelopmentMode() && !allowLessThanOneSecond {
			return 0, fmt.Errorf("polling interval must be at least 60 seconds")
		}
		return time.Duration(number) * time.Second, nil
	case "ms":
		if number < 1000 && !IsDevelopmentMode() && !allowLessThanOneSecond {
			return 0, fmt.Errorf("polling interval must be at least 1000 milliseconds")
		}
		return time.Duration(number) * time.Millisecond, nil
	case "m":
		return time.Duration(number) * time.Minute, nil
	case "h":
		return time.Duration(number) * time.Hour, nil
	case "d":
		return time.Duration(number) * 24 * time.Hour, nil
	case "w":
		return time.Duration(number) * 7 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid time unit")
	}
}
