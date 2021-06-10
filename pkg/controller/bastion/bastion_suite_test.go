// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bastion

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"testing"

	mockgcpclient "github.com/gardener/gardener-extension-provider-gcp/pkg/internal/mock/client"
	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/api/compute/v1"
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
		cluster *extensions.Cluster
		bastion *extensionsv1alpha1.Bastion

		opt  Options
		ctrl *gomock.Controller
	)
	BeforeEach(func() {
		cluster = createGCPTestCluster()
		bastion = createTestBastion()
		ctrl = gomock.NewController(GinkgoT())
	})
	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("getWorkersCIDR", func() {
		It("getWorkersCIDR", func() {
			cidr, err := getWorkersCIDR(createGCPTestCluster())
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
				DiskResourceName,
				NodesResourceName,
				FirewallIngressAllowSSHResourceName,
				FirewallEgressAllowOnlyResourceName,
				FirewallEgressDenyAllResourceName,
			}

			expectedGeneratedNames := []string{
				"clusterName-LetsExceed63LenLimit0-bastion-139c4-disk",
				"clusterName-LetsExceed63LenLimit0-bastion-139c4-nodes",
				"clusterName-LetsExceed63LenLimit0-bastion-139c4-allow-ssh",
				"clusterName-LetsExceed63LenLimit0-bastion-139c4-egress-worker",
				"clusterName-LetsExceed63LenLimit0-bastion-139c4-deny-all",
			}

			baseName, _ := generateBastionBaseResourceName("clusterName", "LetsExceed63LenLimit012345678901234567890123456789012345678901234567890123456789")
			for index, fun := range nameGenerators {
				result := fun(baseName)
				Expect(len(result)).Should(BeNumerically("<", maxLengthForResource), "failed function: %v", runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name())
				Expect(result).Should(Equal(expectedGeneratedNames[index]))
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
			testInput := []byte(`{"zone":"us-west1-a"}`)
			res, err := unmarshalProviderStatus(testInput)
			expectedMarshalOutput := "us-west1-a"

			Expect(err).To(Not(HaveOccurred()))
			Expect(res.Zone).To(Equal(expectedMarshalOutput))
		})
	})

	Describe("check Ingress Permissions", func() {
		It("Should return a string array with ipV4 normalized addresses", func() {
			bastion.Spec.Ingress = []extensionsv1alpha1.BastionIngressPolicy{
				{IPBlock: networkingv1.IPBlock{
					CIDR: "213.69.151.253/24",
				}},
			}
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
			bastion.Status.ProviderStatus = &runtime2.RawExtension{Raw: []byte(`{"zone":"us-west1-a"}`)}
			res, err := getProviderStatus(bastion)
			Expect(err).To(Not(HaveOccurred()))
			Expect(res.Zone).To(Equal("us-west1-a"))
		})
	})

	Describe("check patchFirewallRule ", func() {
		It("should patch firewalls", func() {
			var (
				ctx                = context.TODO()
				firewallName       = fmt.Sprintf("%sfw", "test-")
				client             = mockgcpclient.NewMockInterface(ctrl)
				firewalls          = mockgcpclient.NewMockFirewallsService(ctrl)
				firewallsPatchCall = mockgcpclient.NewMockFirewallsPatchCall(ctrl)
			)
			opt = createTestOptions(opt)

			gomock.InOrder(
				client.EXPECT().Firewalls().Return(firewalls),
				firewalls.EXPECT().Patch(opt.ProjectID, firewallName, patchCIDRs(&opt)).Return(firewallsPatchCall),
				firewallsPatchCall.EXPECT().Context(ctx).Return(firewallsPatchCall),
				firewallsPatchCall.EXPECT().Do(),
			)
			Expect(patchFirewallRule(ctx, client, &opt, firewallName)).To(Succeed())
		})
	})

	Describe("check DeleteFirewalls works", func() {
		It("should delete all firewalls", func() {
			var (
				ctx                 = context.TODO()
				firewallName        = fmt.Sprintf("%sfw", "test-")
				client              = mockgcpclient.NewMockInterface(ctrl)
				firewalls           = mockgcpclient.NewMockFirewallsService(ctrl)
				firewallsDeleteCall = mockgcpclient.NewMockFirewallsDeleteCall(ctrl)
			)
			opt = createTestOptions(opt)

			gomock.InOrder(
				client.EXPECT().Firewalls().Return(firewalls),
				firewalls.EXPECT().Delete(opt.ProjectID, firewallName).Return(firewallsDeleteCall),
				firewallsDeleteCall.EXPECT().Context(ctx).Return(firewallsDeleteCall),
				firewallsDeleteCall.EXPECT().Do(),
			)
			Expect(deleteFirewallRule(ctx, client, &opt, firewallName)).To(Succeed())

		})
	})

	Describe("check PatchCIDRs ", func() {
		It("should return equally", func() {
			opt := &Options{CIDRs: []string{"213.69.151.0/24"}}
			value := &compute.Firewall{SourceRanges: opt.CIDRs}
			Expect(patchCIDRs(opt)).To(Equal(value))
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
	opt.ProjectID = "test-project"
	opt.Zone = "us-west1-a"
	opt.BastionInstanceName = "test-bastion1"
	opt.CIDRs = []string{"213.69.151.0/24"}
	return opt
}
