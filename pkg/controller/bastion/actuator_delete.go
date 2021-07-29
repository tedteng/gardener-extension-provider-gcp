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
	"errors"
	"fmt"
	"time"

	gcpclient "github.com/gardener/gardener-extension-provider-gcp/pkg/internal/client"
	"github.com/gardener/gardener/extensions/pkg/controller"
	ctrlerror "github.com/gardener/gardener/extensions/pkg/controller/error"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Delete(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) error {
	logger := a.logger.WithValues("bastion", client.ObjectKeyFromObject(bastion), "operation", "delete")

	gcpClient, opt, err := createGCPClientAndOptions(ctx, a, bastion, cluster)
	if err != nil {
		return err
	}

	if err := removeFirewallRules(ctx, logger, bastion, gcpClient, opt); err != nil {
		return fmt.Errorf("%w, failed to remove firewall rule", err)
	}

	if err := removeBastionInstance(ctx, logger, gcpClient, opt); err != nil {
		return fmt.Errorf("%w, failed to remove bastion instance", err)
	}

	deleted, err := isInstanceDeleted(ctx, gcpClient, opt)
	if err != nil {
		return fmt.Errorf("%w, failed to check for bastion instance", err)
	}

	if !deleted {
		return &ctrlerror.RequeueAfterError{
			RequeueAfter: 10 * time.Second,
			Cause:        errors.New("bastion instance is still deleting"),
		}
	}

	if err := removeDisk(ctx, logger, gcpClient, opt); err != nil {
		return fmt.Errorf("%w, failed to remove disk", err)
	}

	return nil
}

func removeFirewallRules(ctx context.Context, logger logr.Logger, bastion *extensionsv1alpha1.Bastion, gcpclient gcpclient.Interface, opt *Options) error {
	firewallList := []string{ingressAllowSSH(opt).Name, egressDenyAll(opt).Name, egressAllowOnly(opt).Name}
	for _, firewall := range firewallList {
		if err := deleteFirewallRule(ctx, gcpclient, opt, firewall); err != nil {
			return err
		}
	}
	return nil
}

func removeBastionInstance(ctx context.Context, logger logr.Logger, gcpclient gcpclient.Interface, opt *Options) error {
	instance, err := getBastionInstance(ctx, gcpclient, opt)
	if err != nil {
		return err
	}

	if instance == nil {
		return nil
	}

	if _, err := gcpclient.Instances().Delete(opt.ProjectID, opt.Zone, opt.BastionInstanceName).Context(ctx).Do(); err != nil {
		return fmt.Errorf("%w, failed to terminate bastion instance", err)
	}

	logger.Info("Instance removed", "rule", opt.BastionInstanceName)
	return nil
}

func isInstanceDeleted(ctx context.Context, gcpclient gcpclient.Interface, opt *Options) (bool, error) {
	instance, err := getBastionInstance(ctx, gcpclient, opt)
	if err != nil {
		return false, err
	}

	return instance == nil, nil
}

func removeDisk(ctx context.Context, logger logr.Logger, gcpclient gcpclient.Interface, opt *Options) error {
	disk, err := getDisk(ctx, gcpclient, opt)
	if err != nil {
		return err
	}

	if disk == nil {
		return nil
	}

	if _, err := gcpclient.Disks().Delete(opt.ProjectID, opt.Zone, opt.DiskName).Context(ctx).Do(); err != nil {
		return fmt.Errorf("%w, failed to delete disk", err)
	}

	logger.Info("Disk removed", "rule", opt.DiskName)
	return nil
}
