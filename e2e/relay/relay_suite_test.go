package relay_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var currentT *testing.T

func TestRelay(t *testing.T) {
	currentT = t
	RegisterFailHandler(Fail)
	RunSpecs(t, "Relay Suite")
}
