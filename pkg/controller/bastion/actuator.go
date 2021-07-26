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

	"github.com/gardener/gardener-extension-provider-gcp/pkg/gcp"
	gcpclient "github.com/gardener/gardener-extension-provider-gcp/pkg/internal/client"
	"github.com/gardener/gardener/extensions/pkg/controller/bastion"
	"github.com/gardener/gardener/extensions/pkg/controller/common"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/go-logr/logr"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	corev1 "k8s.io/api/core/v1"
)

const (
	// SSHPort is the default SSH Port used for bastion ingress firewall rule
	SSHPort                 = 22
	errCodeInstanceNotFound = 404
	errCodeFirewallNotFound = 404
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

func (a *actuator) getGCPClient(ctx context.Context, bastion *extensionsv1alpha1.Bastion) (gcpclient.Interface, error) {
	secret := &corev1.Secret{}
	key := kubernetes.Key(bastion.Namespace, v1beta1constants.SecretNameCloudProvider)

	if err := a.Client().Get(ctx, key, secret); err != nil {
		return nil, fmt.Errorf("failed to find %q Secret: %w", v1beta1constants.SecretNameCloudProvider, err)
	}

	data, err := gcp.ReadServiceAccountSecret(secret)
	if err != nil {
		return nil, err
	}

	gcpClient, err := gcpclient.NewFromServiceAccount(ctx, data)
	if err != nil {
		return nil, err
	}
	return gcpClient, nil
}

func (a *actuator) getProjectId(ctx context.Context, bastion *extensionsv1alpha1.Bastion) (string, error) {
	secret := &corev1.Secret{}
	key := kubernetes.Key(bastion.Namespace, v1beta1constants.SecretNameCloudProvider)

	if err := a.Client().Get(ctx, key, secret); err != nil {
		return "", fmt.Errorf("failed to find %q Secret: %w", v1beta1constants.SecretNameCloudProvider, err)
	}

	data, err := gcp.ReadServiceAccountSecret(secret)
	if err != nil {
		return "", err
	}

	return gcp.ExtractServiceAccountProjectID(data)
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
		return fmt.Errorf("%w, could not create firewall rule %s", err, rb.Name)
	}

	logger.Info("Firewall created", "firewall", rb.Name)
	return nil
}

func deletedFirewallRule(ctx context.Context, gcpclient gcpclient.Interface, opt *Options, firewallRuleName string) error {
	if _, err := gcpclient.Firewalls().Delete(opt.ProjectID, firewallRuleName).Context(ctx).Do(); err != nil {
		return fmt.Errorf("%w, failed to delete firewall rule %s", err, firewallRuleName)
	}

	logger.Info("Firewall rule removed", "rule", firewallRuleName)
	return nil
}

func patchFirewallRule(ctx context.Context, gcpclient gcpclient.Interface, opt *Options, firewallRuleName string) error {
	rb := &compute.Firewall{SourceRanges: opt.CIDRs}
	if _, err := gcpclient.Firewalls().Patch(opt.ProjectID, firewallRuleName, rb).Context(ctx).Do(); err != nil {
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
