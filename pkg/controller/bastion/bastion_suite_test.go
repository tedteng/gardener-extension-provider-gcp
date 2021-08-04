package bastion

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	gcpclient "github.com/gardener/gardener-extension-provider-gcp/pkg/internal/client"
	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/common"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime2 "k8s.io/apimachinery/pkg/runtime"
)

func TestBastion(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Bastion Suite")
}

var _ = Describe("Bastion", func() {
	var (
		cluster   *extensions.Cluster
		bastion   *extensionsv1alpha1.Bastion
		ctx       context.Context
		gcpclient gcpclient.Interface
		opt       Options
	)
	BeforeEach(func() {
		cluster = createGCPTestCluster()
		bastion = createTestBastion()
	})

	Describe("getWorkersCIDR", func() {
		It("getWorkersCIDR", func() {
			cidr, err := getWorkersCIDR(createShootTestStruct())
			Expect(err).To(Not(HaveOccurred()))
			Expect(cidr).To(Equal("10.250.0.0/16"))
		})
	})

	Describe("Determine options", func() {
		It("should return options", func() {
			options, err := DetermineOptions(bastion, cluster, "projectID")
			if err != nil {
				fmt.Println(err)
			}

			Expect(options.BastionInstanceName).To(Equal("cluster1-bastionName1-bastion-1cdc8"))
			Expect(options.Zone).To(Equal("us-west1-a"))
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

	Describe("check getZone", func() {
		var testProviderStatusRaw providerStatusRaw
		It("should return an empty string", func() {
			testProviderStatusRaw = providerStatusRaw{""}
			res := getZone(cluster, "us-west", &testProviderStatusRaw)
			Expect(res).To(BeEmpty())
		})

		It("should return a zone string", func() {
			testProviderStatusRaw = providerStatusRaw{"us-west1-a"}
			res := getZone(cluster, "us-west", &testProviderStatusRaw)
			Expect(res).To(Equal("us-west1-a"))
		})
	})

	Describe("check marshalProviderStatus", func() {
		It("should return a JSON object containing a Zone Struct", func() {
			res, err := marshalProviderStatus("us-west1-a")
			expectedMarshalOutput := "{\"zone\":\"us-west1-a\"}"

			Expect(err).To(Not(HaveOccurred()))
			Expect(string(res)).To(Equal(expectedMarshalOutput))
		})
	})

	Describe("check unMarshalProviderStatus", func() {
		It("should update a ProviderStatusRaw Object from a Byte array", func() {
			testInput := []byte("{\"zone\":\"us-west1-a\"}")
			res, err := unmarshalProviderStatus(testInput)
			expectedMarshalOutput := "us-west1-a"

			Expect(err).To(Not(HaveOccurred()))
			Expect(res.Zone).To(Equal(expectedMarshalOutput))
		})
	})

	Describe("check Ingress Permissions", func() {
		It("Should return a string array with ipV4 normalized addresses", func() {
			res, err := ingressPermissions(bastion)
			Expect(err).To(Not(HaveOccurred()))
			Expect(res[0]).To(Equal("213.69.151.0/24"))

		})
	})
	Describe("check Ingress Permissions", func() {
		It("Should return a string array with ipV4 normalized addresses", func() {
			res, err := ingressPermissions(bastion)
			Expect(err).To(Not(HaveOccurred()))
			Expect(res[0]).To(Equal("213.69.151.0/24"))
		})
		It("Should throw an error with invalid CIDR entry", func() {
			bastion.Spec.Ingress = []extensionsv1alpha1.BastionIngressPolicy{
				{IPBlock: networkingv1.IPBlock{
					CIDR: "1234",
				}},
			}
			res, err := ingressPermissions(bastion)
			Expect(err).To(HaveOccurred())
			Expect(res).To(BeEmpty())
		})
	})

	Describe("check getProviderStatus", func() {
		It("Should return an error and nil", func() {

			res, err := getProviderStatus(bastion)
			Expect(err).To(BeNil())
			Expect(res).To(BeNil())
		})
		It("Should return a providerStatusRaw struct", func() {
			bastion.Status.ProviderStatus = &runtime2.RawExtension{Raw: []byte("{\"zone\":\"us-west1-a\"}")}
			res, err := getProviderStatus(bastion)
			Expect(err).To(Not(HaveOccurred()))
			Expect(res.Zone).To(Equal("us-west1-a"))
		})
	})

	Describe("check return values", func() {
		It("Should return base plus disk", func() {
			res := diskResourceName("base")
			Expect(res).To(Equal("base-disk"))
		})
		It("Should return base plus nodes", func() {
			res := nodesResourceName("base")
			Expect(res).To(Equal("base-nodes"))
		})
		It("Should return base plus allow-ssh", func() {
			res := firewallIngressAllowSSHResourceName("base")
			Expect(res).To(Equal("base-allow-ssh"))
		})
		It("Should return base plus egress-worker", func() {
			res := firewallEgressAllowOnlyResourceName("base")
			Expect(res).To(Equal("base-egress-worker"))
		})
		It("Should return base plus deny-all", func() {
			res := firewallEgressDenyAllResourceName("base")
			Expect(res).To(Equal("base-deny-all"))
		})
	})

	Describe("check getBastionInstance", func() {
		It("Should return Bastion Instance", func() {
			opt = createTestOptions(opt)
			ctx = context.Background()
			a := &actuator{common.ClientContext, logger}
			gcpclient, _, _ = createGCPClientAndOptions(ctx, a, bastion, cluster)
			res, err := getBastionInstance(ctx, gcpclient, &opt)

			Expect(err).To(Not(HaveOccurred()))
			Expect(res.Name).To(Equal("test-bastion1"))

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

func createGCPTestCluster() *extensions.Cluster {
	cluster := &controller.Cluster{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster1"},
		Shoot:      createShootTestStruct(),
		CloudProfile: &gardencorev1beta1.CloudProfile{
			Spec: gardencorev1beta1.CloudProfileSpec{
				Regions: []gardencorev1beta1.Region{
					{Name: "regionName"},
					{Name: "us-west", Zones: []gardencorev1beta1.AvailabilityZone{
						{Name: "us-west1-a"},
						{Name: "us-west1-b"},
					}},
				},
			},
		},
	}
	return cluster
}

func createTestBastion() *extensionsv1alpha1.Bastion {
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
	return bastion
}

func createTestOptions(opt Options) Options {
	opt.ProjectID = "sap-se-gcp-scp-k8s-dev"
	opt.Zone = "us-west1-a"
	opt.BastionInstanceName = "test-bastion1"
	return opt
}
