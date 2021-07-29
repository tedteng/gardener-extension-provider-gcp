package bastion

import (
	"reflect"
	"runtime"
	"testing"
)

func Test_generateBastionComputeInstanceName(t *testing.T) {
	res, err := generateBastionBaseResourceName("clusterName", "shortName")
	if err != nil {
		t.Error(err)
	}
	if res != "clusterName-shortName-bastion-79641" {
		t.Errorf("generateBastionBaseResourceName() generated wrong name, have got %s", res)
	}
}

func Test_generateBastionComputeInstanceNameLen(t *testing.T) {
	res, err := generateBastionBaseResourceName("clusterName", "LetsExceed63LenLimit012345678901234567890123456789012345678901234567890123456789")
	if err != nil {
		t.Error(err)
	}
	if len([]rune(res)) != 47 {
		t.Error("generateBastionBaseResourceName() expected name should be 47 length")
	}
	if res != "clusterName-LetsExceed63LenLimit0-bastion-139c4" {
		t.Errorf("generateBastionBaseResourceName() generated wrong name, have got %s", res)
	}
}

func Test_generateBastionComputeInstanceClash(t *testing.T) {
	res, err := generateBastionBaseResourceName("a23456789012345678901234567890", "123")
	if err != nil {
		t.Error(err)
	}
	res2, err2 := generateBastionBaseResourceName("a23456789012345678901234567890", "124")
	if err2 != nil {
		t.Error(err)
	}
	if res == res2 {
		t.Error("generateBastionBaseResourceName() generate equal names for different resources")
	}
}

func Test_ResourceNameFitTheSize(t *testing.T) {
	nameGenerators := []func(string) string{
		diskResourceName,
		nodesResourceName,
		firewallIngressAllowSSHResourceName,
		firewallEgressAllowOnlyResourceName,
		firewallEgressDenyAllResourceName,
	}

	baseName, err := generateBastionBaseResourceName("clusterName", "LetsExceed63LenLimit012345678901234567890123456789012345678901234567890123456789")
	if err != nil {
		t.Error(err)
	}
	for _, fun := range nameGenerators {
		result := fun(baseName)
		if len(result) > maxLengthForResource {
			t.Errorf("function %v generate name longer then it's allowed", runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name())
		}
	}
}
