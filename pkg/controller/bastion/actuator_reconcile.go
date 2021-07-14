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
	"strconv"
	"time"

	gcpclient "github.com/gardener/gardener-extension-provider-gcp/pkg/internal/client"
	"github.com/gardener/gardener/extensions/pkg/controller"
	ctrlerror "github.com/gardener/gardener/extensions/pkg/controller/error"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *actuator) Reconcile(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) error {
	logger := a.logger.WithValues("bastion", client.ObjectKeyFromObject(bastion), "operation", "reconcile")

	gcpclient, err := a.getGCPClient(ctx, bastion)
	if err != nil {
		return errors.Wrap(err, "failed to create GCP client")
	}

	opt, err := DetermineOptions(ctx, bastion, cluster)
	if err != nil {
		return errors.Wrap(err, "failed to setup GCP options")
	}

	err = ensureFirewallRule(ctx, bastion, gcpclient, opt)
	if err != nil {
		return errors.Wrap(err, "failed to ensure firewall rule")
	}

	endpoints, err := ensureBastionInstance(ctx, logger, bastion, gcpclient, opt)
	if err != nil {
		return errors.Wrap(err, "failed to ensure bastion instance")
	}

	if !endpoints.Ready() {
		return &ctrlerror.RequeueAfterError{
			// requeue rather soon, so that the user (most likely gardenctl eventually)
			// doesn't have to wait too long for the public endpoint to become available
			RequeueAfter: 5 * time.Second,
			Cause:        errors.New("bastion instance has no public/private endpoints yet"),
		}
	}

	// once a public endpoint is available, publish the endpoint on the
	// Bastion resource to notify upstream about the ready instance
	return controller.TryUpdateStatus(ctx, retry.DefaultBackoff, a.Client(), bastion, func() error {
		bastion.Status.Ingress = *endpoints.public
		return nil
	})

}

func ensureFirewallRule(ctx context.Context, bastion *extensionsv1alpha1.Bastion, gcpclient gcpclient.Interface, opt *Options) error {
	firewall, err := getFirewallRule(ctx, gcpclient, opt)
	if err != nil {
		return errors.Wrap(err, "could not get firewall rule")
	}

	// create firewall if it doesn't exist yet
	if firewall == nil {
		return createFirewallRule(ctx, gcpclient, opt)
	}

	return nil
}

func createFirewallRule(ctx context.Context, gcpclient gcpclient.Interface, opt *Options) error {
	rb := &compute.Firewall{
		Allowed:      []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{strconv.Itoa(SSHPort)}}},
		Description:  "SSH access for Bastion",
		Direction:    "INGRESS",
		TargetTags:   []string{"gardenctl"},
		Name:         opt.FirewallName,
		Network:      "projects/" + opt.ProjectID + "/global/networks/" + opt.Shoot.Name,
		SourceRanges: []string{opt.PublicIP},
	}
	_, err := gcpclient.Firewalls().Insert(opt.ProjectID, rb).Context(ctx).Do()
	if err != nil {
		return errors.Wrap(err, "could not create firewall rule")
	}

	logger.Info("Firewall created", "firewall", opt.FirewallName)
	return nil
}

func ensureBastionInstance(ctx context.Context, logger logr.Logger, bastion *extensionsv1alpha1.Bastion, gcpclient gcpclient.Interface, opt *Options) (*bastionEndpoints, error) {
	// check if the instance already exists and has an IP
	endpoints, err := getInstanceEndpoints(ctx, gcpclient, opt)
	if err != nil { // could not check for instance
		return nil, errors.Wrap(err, "failed to check for GCP Bastion instance")
	}

	// instance exists, though it may not be ready yet
	if endpoints != nil {
		return endpoints, nil
	}

	logger.Info("Running new bastion instance")

	disk := &compute.Disk{
		Description: "Bastion disk",
		Name:        opt.DiskName,
		SizeGb:      10,
		SourceImage: "projects/debian-cloud/global/images/family/debian-10",
		Zone:        opt.Zone,
	}

	_, err = gcpclient.Disks().Insert(opt.ProjectID, opt.Zone, disk).Context(ctx).Do()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create disk")
	}

	logger.Info("Disk created", "disk", opt.DiskName)

	disks := []*compute.AttachedDisk{
		{
			AutoDelete: true,
			Boot:       true,
			DiskSizeGb: 10,
			Source:     "projects/" + opt.ProjectID + "/zones/" + opt.Zone + "/disks/" + opt.DiskName,
			Mode:       "READ_WRITE",
		},
	}

	networkInterfaces := []*compute.NetworkInterface{
		{
			Network:       "projects/" + opt.ProjectID + "/global/networks/" + opt.Shoot.Name,
			Subnetwork:    "regions/" + opt.Region + "/subnetworks/" + opt.Subnetwork,
			AccessConfigs: []*compute.AccessConfig{{Name: "External NAT", Type: "ONE_TO_ONE_NAT"}},
		},
	}

	machineType := "zones/" + opt.Zone + "/machineTypes/n1-standard-1"

	instance, err := gcpclient.Instances().Get(opt.ProjectID, opt.Zone, opt.BastionInstanceName).Context(ctx).Do()
	if err != nil {
		googleError, ok := err.(*googleapi.Error)
		if !ok {
			return nil, errors.New("type unknown")
		}

		if googleError.Code != 404 {
			return nil, errors.Wrap(err, "failed to get compute instance")
		}
	}

	value := string(bastion.Spec.UserData)
	metadataItems := []*compute.MetadataItems{
		{
			Key:   "startup-script",
			Value: &value,
		},
	}

	if instance != nil {
		logger.Info("Existing bastion compute instance found", "compute_instance_name", instance.Name)
	} else {
		instance := &compute.Instance{
			Disks:              disks,
			DeletionProtection: false,
			Description:        "Bastion Instance",
			Name:               opt.BastionInstanceName,
			Zone:               opt.Zone,
			MachineType:        machineType,
			NetworkInterfaces:  networkInterfaces,
			Tags:               &compute.Tags{Items: []string{"gardenctl"}},
			Metadata:           &compute.Metadata{Items: metadataItems},
		}

		_, err = gcpclient.Instances().Insert(opt.ProjectID, opt.Zone, instance).Context(ctx).Do()
		if err != nil {
			return nil, errors.Wrap(err, "failed to create instance")
		}
	}

	return getInstanceEndpoints(ctx, gcpclient, opt)
}

func getInstanceEndpoints(ctx context.Context, gcpclient gcpclient.Interface, opt *Options) (*bastionEndpoints, error) {
	instance, err := getBastionInstance(ctx, gcpclient, opt)
	if err != nil {
		return nil, err
	}

	if instance == nil {
		return nil, nil
	}

	endpoints := &bastionEndpoints{}

	if ingress := addressToIngress(&instance.Name, &instance.NetworkInterfaces[0].NetworkIP); ingress != nil {
		endpoints.private = ingress
	}

	if instance.NetworkInterfaces == nil || len(instance.NetworkInterfaces) == 0 {
		err := errors.New("no network interfaces found")
		logger.Error(err, "no network interfaces found", "compute_instance", instance.Name)
		return nil, err
	}

	if instance.NetworkInterfaces[0].AccessConfigs == nil || len(instance.NetworkInterfaces[0].AccessConfigs) == 0 {
		err := errors.New("no access config found for network interface")
		logger.Error(err, "no access config found for network interface", "compute_instance", instance.Name)
		return nil, err
	}

	if ingress := addressToIngress(&instance.Name, &instance.NetworkInterfaces[0].AccessConfigs[0].NatIP); ingress != nil {
		endpoints.public = ingress
	}

	return endpoints, nil
}

// bastionEndpoints collects the endpoints the bastion host provides; the
// private endpoint is important for opening a port on the worker node
// ingress firewall rule to allow SSH from that node, the public endpoint is where
// the enduser connects to to establish the SSH connection.
type bastionEndpoints struct {
	private *corev1.LoadBalancerIngress
	public  *corev1.LoadBalancerIngress
}

// Ready returns true if both public and private interfaces each have either
// an IP or a hostname or both.
func (be *bastionEndpoints) Ready() bool {
	return be != nil && IngressReady(be.private) && IngressReady(be.public)
}

// IngressReady returns true if either an IP or a hostname or both are set.
func IngressReady(ingress *corev1.LoadBalancerIngress) bool {
	return ingress != nil && (ingress.Hostname != "" || ingress.IP != "")
}

// addressToIngress converts the IP address into a
// corev1.LoadBalancerIngress resource. If both arguments are nil, then
// nil is returned.
func addressToIngress(hostName *string, ipAddress *string) *corev1.LoadBalancerIngress {
	var ingress *corev1.LoadBalancerIngress

	if ipAddress != nil {
		ingress = &corev1.LoadBalancerIngress{}
		if hostName != nil {
			ingress.Hostname = *hostName
		}

		if ipAddress != nil {
			ingress.IP = *ipAddress
		}
	}

	return ingress
}
