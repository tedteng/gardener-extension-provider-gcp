package bastion

import (
	"fmt"
	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			cidr, err := getWorkersCIDR(createShootTestStruct())
			Expect(err).To(Not(HaveOccurred()))
			Expect(cidr).To(Equal("10.250.0.0/16"))
		})
	})

	Describe("Determine options", func() {
		It("should return options", func() {

			cluster := &controller.Cluster{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster1"},
				Shoot:      createShootTestStruct(),
				CloudProfile: &gardencorev1beta1.CloudProfile{
					Spec: gardencorev1beta1.CloudProfileSpec{
						Regions: []gardencorev1beta1.Region{
							{Name: "regionName"},
							{Name: "us-west", Zones: []gardencorev1beta1.AvailabilityZone{
								{Name: "us-west-a"},
								{Name: "us-west-b"},
							}},
						},
					},
				},
			}

			bastion := &extensionsv1alpha1.Bastion{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bastionName1",
				},
				Spec: extensionsv1alpha1.BastionSpec{
					DefaultSpec: extensionsv1alpha1.DefaultSpec{},
					UserData:    nil,
					Ingress: []extensionsv1alpha1.BastionIngressPolicy{
						{IPBlock: networkingv1.IPBlock{
							CIDR: "213.69.151.0/24",
						}},
					},
				},
			}
			options, err := DetermineOptions(bastion, cluster, "projectID")
			if err != nil {
				fmt.Println(err)
			}

			Expect(options.BastionInstanceName).To(Equal("cluster1-bastionName1-bastion-1cdc8"))
			Expect(options.Zone).To(Equal("us-west-a"))
			Expect(options.DiskName).To(Equal("cluster1-bastionName1-bastion-1cdc8-disk"))
			Expect(options.CIDRs).To(Equal([]string{"213.69.151.0/24"}))
			Expect(options.Subnetwork).To(Equal("regions/us-west/subnetworks/cluster1-nodes"))
			Expect(options.ProjectID).To(Equal("projectID"))
			Expect(options.Network).To(Equal("projects/projectID/global/networks/cluster1"))
			Expect(options.WorkersCIDR).To(Equal("10.250.0.0/16"))
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

func createShootTestStruct() *gardencorev1beta1.Shoot {
	json := `{"apiVersion": "gcp.provider.extensions.gardener.cloud/v1alpha1","kind": "InfrastructureConfig", "networks": {"workers": "10.250.0.0/16"}}`
	shoot := &gardencorev1beta1.Shoot{
		Spec: gardencorev1beta1.ShootSpec{
			Region: "us-west",
			Provider: gardencorev1beta1.Provider{
				InfrastructureConfig: &runtime2.RawExtension{
					Raw: []byte(json),
				}}},
	}
	return shoot
}
