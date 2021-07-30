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
	"encoding/json"
	"fmt"
	"strings"

	gcpapi "github.com/gardener/gardener-extension-provider-gcp/pkg/apis/gcp"
	"github.com/gardener/gardener-extension-provider-gcp/pkg/gcp"
	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	v1 "k8s.io/api/core/v1"

	gcpclient "github.com/gardener/gardener-extension-provider-gcp/pkg/internal/client"
	"github.com/gardener/gardener/extensions/pkg/controller/bastion"
	"github.com/gardener/gardener/extensions/pkg/controller/common"
	"github.com/go-logr/logr"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
)

const (
	// SSHPort is the default SSH Port used for bastion ingress firewall rule
	SSHPort                 = 22
	errCodeInstanceNotFound = 404
	errCodeFirewallNotFound = 404
	errCodeFirewallExists   = 409
	errCodeDiskNotFound     = 404
)

type actuator struct {
	common.ClientContext

	logger logr.Logger
}

func newActuator() bastion.Actuator {
	return &actuator{
		logger: logger,
	}
}

func getBastionInstance(ctx context.Context, gcpclient gcpclient.Interface, opt *Options) (*compute.Instance, error) {
	instance, err := gcpclient.Instances().Get(opt.ProjectID, opt.Zone, opt.BastionInstanceName).Context(ctx).Do()
	if err != nil {
		if googleError, ok := err.(*googleapi.Error); ok && googleError.Code == errCodeInstanceNotFound {
			logger.Info("Instance not found,", "instance_name", opt.BastionInstanceName)
			return nil, nil
		}
		return nil, err
	}
	return instance, nil
}

func getFirewallRule(ctx context.Context, gcpclient gcpclient.Interface, opt *Options, firewallRuleName string) (*compute.Firewall, error) {
	firewall, err := gcpclient.Firewalls().Get(opt.ProjectID, firewallRuleName).Context(ctx).Do()
	if err != nil {
		if googleError, ok := err.(*googleapi.Error); ok && googleError.Code == errCodeFirewallNotFound {
			logger.Info("Firewall rule not found,", "firewall_rule_name", firewallRuleName)
			return nil, nil
		}
		return nil, err
	}
	return firewall, nil
}

func createFirewallRule(ctx context.Context, gcpclient gcpclient.Interface, opt *Options, rb *compute.Firewall) error {
	if _, err := gcpclient.Firewalls().Insert(opt.ProjectID, rb).Context(ctx).Do(); err != nil {
		if googleError, ok := err.(*googleapi.Error); ok && googleError.Code == errCodeFirewallExists {
			logger.Info("Firewall rule already exits,", "firewall_rule_name", rb.Name)
			return nil
		}
		return fmt.Errorf("%w, could not create firewall rule %s", err, rb.Name)
	}

	logger.Info("Firewall created", "firewall", rb.Name)
	return nil
}

func deleteFirewallRule(ctx context.Context, gcpclient gcpclient.Interface, opt *Options, firewallRuleName string) error {
	if _, err := gcpclient.Firewalls().Delete(opt.ProjectID, firewallRuleName).Context(ctx).Do(); err != nil {
		if googleError, ok := err.(*googleapi.Error); ok && googleError.Code == errCodeFirewallNotFound {
			logger.Info("Firewall rule not found,", "firewall_rule_name", firewallRuleName)
			return nil
		}
		return fmt.Errorf("%w, failed to delete firewall rule %s", err, firewallRuleName)
	}

	logger.Info("Firewall rule removed", "rule", firewallRuleName)
	return nil
}

func patchFirewallRule(ctx context.Context, gcpclient gcpclient.Interface, opt *Options, firewallRuleName string) error {
	if _, err := gcpclient.Firewalls().Patch(opt.ProjectID, firewallRuleName, patchCIDRs(opt)).Context(ctx).Do(); err != nil {
		return err
	}
	return nil
}

func getDisk(ctx context.Context, gcpclient gcpclient.Interface, opt *Options) (*compute.Disk, error) {
	disk, err := gcpclient.Disks().Get(opt.ProjectID, opt.Zone, opt.DiskName).Context(ctx).Do()
	if err != nil {
		if googleError, ok := err.(*googleapi.Error); ok && googleError.Code == errCodeDiskNotFound {
			logger.Info("Disk not found,", "disk_name", opt.DiskName)
			return nil, nil
		}
		return nil, err
	}
	return disk, nil
}

func createGCPClientAndOptions(ctx context.Context, a *actuator, bastion *v1alpha1.Bastion, cluster *controller.Cluster) (gcpclient.Interface, *Options, error) {
	serviceAccount, err := gcp.GetServiceAccount(ctx, a.Client(), v1.SecretReference{Namespace: bastion.Namespace, Name: constants.SecretNameCloudProvider})
	if err != nil {
		return nil, nil, fmt.Errorf("%w, failed to get serviceaccount", err)
	}

	gcpClient, err := gcpclient.NewFromServiceAccount(ctx, serviceAccount.Raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w, failed to create GCP client", err)
	}

	opt, err := DetermineOptions(bastion, cluster, serviceAccount.ProjectID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w, failed to determine Options", err)
	}

	return gcpClient, opt, nil
}

func getWorkersCIDR(shoot *gardencorev1beta1.Shoot) (string, error) {
	InfrastructureConfig := &gcpapi.InfrastructureConfig{}
	err := json.Unmarshal(shoot.Spec.Provider.InfrastructureConfig.Raw, InfrastructureConfig)
	if err != nil {
		return "", err
	}
	return InfrastructureConfig.Networks.Workers, nil
}

func getDefaultGCPZone(ctx context.Context, gcpclient gcpclient.Interface, opt *Options, region string) (string, error) {
	resp, err := gcpclient.Regions().Get(opt.ProjectID, region).Context(ctx).Do()
	if err != nil {
		return "", err
	}
	if len(resp.Zones) > 0 {
		zone := strings.Split(resp.Zones[0], "/")
		return zone[(len(zone) - 1)], nil
	}
	return "", fmt.Errorf("no available zones in GCP region:%s", region)
}
