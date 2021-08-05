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

package bastion_test

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	gcpinstall "github.com/gardener/gardener-extension-provider-gcp/pkg/apis/gcp/install"
	bastionctrl "github.com/gardener/gardener-extension-provider-gcp/pkg/controller/bastion"
	"github.com/gardener/gardener-extension-provider-gcp/pkg/gcp"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	gardenerutils "github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
// workersSubnetCIDR = "192.168.20.0/24" // this is purposefully not normalised
// cidrv4                  = "192.168.20.0/24"
// errCodeFirewallNotFound = 404
)

var (
	serviceAccount = flag.String("service-account", "", "Service account containing credentials for the GCP API")
	region         = flag.String("region", "", "GCP region")
)

func validateFlags() {
	if len(*serviceAccount) == 0 {
		panic("--service-account flag is not specified")
	}
	if len(*region) == 0 {
		panic("--region flag is not specified")
	}
}

var _ = Describe("Bastion tests", func() {
	var (
		ctx = context.Background()

		logger         *logrus.Entry
		projectID      string
		computeService *compute.Service

		// loger logr.Logger
		// clientcontext *common.ClientContext

		// extensionscluster *extensionsv1alpha1.Cluster

		// cluster *controller.Cluster
		// infrastructureConfig *gcpv1alpha1.InfrastructureConfig
		testEnv   *envtest.Environment
		mgrCancel context.CancelFunc
		c         client.Client

		// opt            *bastionctrl.Options

		// bastion *extensionsv1alpha1.Bastion
		// newBastion *bastionctrl.Actuator
		// iamService *iam.Service

	)

	randString, err := randomString()
	Expect(err).NotTo(HaveOccurred())

	name := fmt.Sprintf("gcp-bastion-it--%s", randString)

	BeforeSuite(func() {
		repoRoot := filepath.Join("..", "..", "..")

		// enable manager logs
		logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(GinkgoWriter)))

		log := logrus.New()
		log.SetOutput(GinkgoWriter)
		logger = logrus.NewEntry(log)

		By("starting test environment")
		testEnv = &envtest.Environment{
			UseExistingCluster: pointer.BoolPtr(true),
			CRDInstallOptions: envtest.CRDInstallOptions{
				Paths: []string{
					filepath.Join(repoRoot, "example", "20-crd-bastion.yaml"),
					filepath.Join(repoRoot, "example", "20-crd-cluster.yaml"),
				},
			},
		}

		cfg, err := testEnv.Start()
		Expect(err).ToNot(HaveOccurred())
		Expect(cfg).ToNot(BeNil())

		By("setup manager")
		mgr, err := manager.New(cfg, manager.Options{
			MetricsBindAddress: "0",
		})
		Expect(err).ToNot(HaveOccurred())

		Expect(extensionsv1alpha1.AddToScheme(mgr.GetScheme())).To(Succeed())
		Expect(gcpinstall.AddToScheme(mgr.GetScheme())).To(Succeed())

		Expect(bastionctrl.AddToManager(mgr)).To(Succeed())

		var mgrContext context.Context
		mgrContext, mgrCancel = context.WithCancel(ctx)

		By("start manager")
		go func() {
			err := mgr.Start(mgrContext)
			Expect(err).NotTo(HaveOccurred())
		}()

		// test client should be uncached and independent from the tested manager
		c, err = client.New(cfg, client.Options{
			Scheme: mgr.GetScheme(),
			Mapper: mgr.GetRESTMapper(),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(c).NotTo(BeNil())

		flag.Parse()
		validateFlags()

		projectID, err = gcp.ExtractServiceAccountProjectID([]byte(*serviceAccount))
		Expect(err).NotTo(HaveOccurred())
		computeService, err = compute.NewService(ctx, option.WithCredentialsJSON([]byte(*serviceAccount)), option.WithScopes(compute.CloudPlatformScope))
		Expect(err).NotTo(HaveOccurred())

		// bastion = createTestBastion(name)
		// cluster = createGCPTestCluster(name)

	})

	AfterSuite(func() {
		defer func() {
			By("stopping manager")
			mgrCancel()
		}()

		By("running cleanup actions")
		framework.RunCleanupActions()

		By("stopping test environment")
		Expect(testEnv.Stop()).To(Succeed())
	})

	It("should successfully create and delete", func() {
		By("setup Infrastructure")
		networkName := name

		err = prepareNewNetwork(ctx, logger, projectID, computeService, networkName)
		Expect(err).NotTo(HaveOccurred())

		framework.AddCleanupAction(func() {
			err = teardownNetwork(ctx, logger, projectID, computeService, networkName)
			Expect(err).NotTo(HaveOccurred())
		})

		// By("setup bastion")

		// newBastion := bastionctrl.NewActuator()

		// err = newBastion.Reconcile(ctx, bastion, cluster)
		// Expect(err).NotTo(HaveOccurred())
		// framework.AddCleanupAction(func() {
		// 	newBastion.Delete(ctx, bastion, cluster)

		// 	By("verify bastion deletion")
		// 	verifyDeletion(ctx, gcpClient, options)
		// })

		// By("wait until bastion is reconciled")
		// Expect(extensions.WaitUntilExtensionObjectReady(
		// 	ctx,
		// 	c,
		// 	logger,
		// 	bastion,
		// 	extensionsv1alpha1.BastionResource,
		// 	10*time.Second,
		// 	30*time.Second,
		// 	5*time.Minute,
		// 	nil,
		// )).To(Succeed())

		// // update the options to have the just created security group's ID
		// securityGroup := getSecurityGroup(ctx, awsClient, options, options.BastionSecurityGroupName)
		// options.BastionSecurityGroupID = *securityGroup.GroupId

		// By("refetch bastion resource")
		// Expect(c.Get(ctx, client.ObjectKey{Namespace: bastion.Namespace, Name: bastion.Name}, bastion)).To(Succeed())

		// By("verify the bastion's status contains endpoints")
		// Expect(bastionctrl.IngressReady(&bastion.Status.Ingress)).To(BeTrue())

		// By("verify cloud resources")
		// verifyCreation(ctx, awsClient, options)
	})
})

func randomString() (string, error) {
	suffix, err := gardenerutils.GenerateRandomStringFromCharset(5, "0123456789abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		return "", err
	}

	return suffix, nil
}

func prepareNewNetwork(ctx context.Context, logger *logrus.Entry, project string, computeService *compute.Service, networkName string) error {
	network := &compute.Network{
		Name:                  networkName,
		AutoCreateSubnetworks: false,
		RoutingConfig: &compute.NetworkRoutingConfig{
			RoutingMode: "REGIONAL",
		},
		ForceSendFields: []string{"AutoCreateSubnetworks"},
	}
	networkOp, err := computeService.Networks.Insert(project, network).Context(ctx).Do()
	if err != nil {
		return err
	}
	logger.Info("Waiting until network is created...", "network ", networkName)
	if err := waitForOperation(ctx, project, computeService, networkOp); err != nil {
		return err
	}

	return nil
}

func teardownNetwork(ctx context.Context, logger *logrus.Entry, project string, computeService *compute.Service, networkName string) error {
	networkOp, err := computeService.Networks.Delete(project, networkName).Context(ctx).Do()
	if err != nil {
		return err
	}

	logger.Info("Waiting until network is deleted...", "network ", networkName)
	if err := waitForOperation(ctx, project, computeService, networkOp); err != nil {
		return err
	}

	return nil
}

func waitForOperation(ctx context.Context, project string, computeService *compute.Service, op *compute.Operation) error {
	return wait.PollUntil(5*time.Second, func() (bool, error) {
		var (
			currentOp *compute.Operation
			err       error
		)

		if op.Region != "" {
			region := getResourceNameFromSelfLink(op.Region)
			currentOp, err = computeService.RegionOperations.Get(project, region, op.Name).Context(ctx).Do()
		} else {
			currentOp, err = computeService.GlobalOperations.Get(project, op.Name).Context(ctx).Do()
		}

		if err != nil {
			return false, err
		}
		return currentOp.Status == "DONE", nil
	}, ctx.Done())
}

func getResourceNameFromSelfLink(link string) string {
	parts := strings.Split(link, "/")
	return parts[len(parts)-1]
}

// func createTestBastion(name string) *extensionsv1alpha1.Bastion {
// 	bastion := &extensionsv1alpha1.Bastion{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name: name + "-bastion",
// 		},
// 		Spec: extensionsv1alpha1.BastionSpec{
// 			DefaultSpec: extensionsv1alpha1.DefaultSpec{},
// 			UserData:    nil,
// 			Ingress: []extensionsv1alpha1.BastionIngressPolicy{
// 				{IPBlock: networkingv1.IPBlock{
// 					CIDR: workersSubnetCIDR,
// 				}},
// 			},
// 		},
// 	}
// 	return bastion
// }

// func createInfrastructure() *gcpv1alpha1.InfrastructureConfig {
// 	infrastructureConfig := &gcpv1alpha1.InfrastructureConfig{
// 		TypeMeta: metav1.TypeMeta{
// 			APIVersion: gcpv1alpha1.SchemeGroupVersion.String(),
// 			Kind:       "InfrastructureConfig",
// 		},
// 		Networks: gcpv1alpha1.NetworkConfig{
// 			Workers: workersSubnetCIDR,
// 		},
// 	}
// 	return infrastructureConfig
// }

// func createShootTestStruct() *gardencorev1beta1.Shoot {
// 	json, _ := json.Marshal(createInfrastructure())

// 	shoot := &gardencorev1beta1.Shoot{
// 		Spec: gardencorev1beta1.ShootSpec{
// 			Region: "us-west",
// 			Provider: gardencorev1beta1.Provider{
// 				InfrastructureConfig: &runtime.RawExtension{
// 					Raw: []byte(json),
// 				}}},
// 	}
// 	return shoot
// }

// func createGCPTestCluster(name string) *extensions.Cluster {
// 	cluster := &controller.Cluster{
// 		ObjectMeta: metav1.ObjectMeta{Name: name},
// 		Shoot:      createShootTestStruct(),
// 		CloudProfile: &gardencorev1beta1.CloudProfile{
// 			Spec: gardencorev1beta1.CloudProfileSpec{
// 				Regions: []gardencorev1beta1.Region{
// 					{Name: *region},
// 					{Name: "us-west", Zones: []gardencorev1beta1.AvailabilityZone{
// 						{Name: "us-west1-a"},
// 						{Name: "us-west1-b"},
// 					}},
// 				},
// 			},
// 		},
// 	}
// 	return cluster
// }
