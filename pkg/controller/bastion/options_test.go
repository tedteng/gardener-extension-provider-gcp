package bastion

import (
	"strings"
	"testing"
)

func Test_generateBastionComputeInstanceName(t *testing.T) {
	res, err := generateBastionBaseResourceName("clusterName", "shortName")
	if err != nil {
		t.Errorf("generateBastionBaseResourceName() error = %v,", err)
	}
	if !strings.HasPrefix(res, "clusterName-shortName-bastion-") {
		t.Errorf("generateBastionBaseResourceName() generated wrong name, have got %s", res)
	}
}

func Test_generateBastionComputeInstanceNameLen(t *testing.T) {
	res, err := generateBastionBaseResourceName("clusterName", "LetsExceed63LenLimit012345678901234567890123456789012345678901234567890123456789")
	if err != nil {
		t.Errorf("generateBastionBaseResourceName() error = %v,", err)
	}
	if len([]rune(res)) != 47 {
		t.Error("generateBastionBaseResourceName() expected name should be 47 length")
	}
	if !strings.HasPrefix(res, "clusterName-LetsExceed63LenLimit0-bastion-") {
		t.Errorf("generateBastionBaseResourceName() generated wrong name, have got %s", res)
	}

}
