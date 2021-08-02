package bastion

import (
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	runtime2 "k8s.io/apimachinery/pkg/runtime"
	"reflect"
	"runtime"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestBastion(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Bastion Suite")
}

var _ = Describe("Bastion", func() {

	Describe("getWorkersCIDR", func() {
		It("getWorkersCIDR", func() {

			json := `{"apiVersion": "gcp.provider.extensions.gardener.cloud/v1alpha1","kind": "InfrastructureConfig", "networks": {"workers": "10.250.0.0/16"}}`
			shoot := &gardencorev1beta1.Shoot{
				Spec: gardencorev1beta1.ShootSpec{
					Provider: gardencorev1beta1.Provider{
						InfrastructureConfig: &runtime2.RawExtension{
							Raw: []byte(json),
						}}},
			}
			cidr, err := getWorkersCIDR(shoot)
			Expect(err).To(Not(HaveOccurred()))
			Expect(cidr).To(Equal("10.250.0.0/16"))
		})
	})

	Describe("check Names generations", func() {
		It("should generate idempotent name", func() {
			expected := "clusterName-shortName-bastion-79641"

			res, err := generateBastionBaseResourceName("clusterName", "shortName")
			Expect(err).To(Not(HaveOccurred()))
			Expect(res).To(Equal(expected))

			res, err = generateBastionBaseResourceName("clusterName", "shortName")
			Expect(err).To(Not(HaveOccurred()))
			Expect(res).To(Equal(expected))
		})

		It("should generate a name not exceeding a certain length", func() {
			res, err := generateBastionBaseResourceName("clusterName", "LetsExceed63LenLimit012345678901234567890123456789012345678901234567890123456789")
			Expect(err).To(Not(HaveOccurred()))
			Expect(res).To(Equal("clusterName-LetsExceed63LenLimit0-bastion-139c4"))
		})

		It("should generate a unique name even if inputs values have minor deviations", func() {
			res, _ := generateBastionBaseResourceName("1", "1")
			res2, _ := generateBastionBaseResourceName("1", "2")
			Expect(res).ToNot(Equal(res2))
		})

		It("should generate names and fit maximum length", func() {
			nameGenerators := []func(string) string{
				diskResourceName,
				nodesResourceName,
				firewallIngressAllowSSHResourceName,
				firewallEgressAllowOnlyResourceName,
				firewallEgressDenyAllResourceName,
			}

			baseName, _ := generateBastionBaseResourceName("clusterName", "LetsExceed63LenLimit012345678901234567890123456789012345678901234567890123456789")
			for _, fun := range nameGenerators {
				result := fun(baseName)
				Expect(len(result)).Should(BeNumerically("<", maxLengthForResource), "failed function: %v", runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name())
			}
		})
	})
})
