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
	"fmt"
	"net"

	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
)

// Options contains provider-related information required for setting up
// a bastion instance. This struct combines precomputed values like the
// bastion instance name with the IDs of pre-existing cloud provider
// resources, like the Firewall name, subnet name etc.
type Options struct {
	Shoot               *gardencorev1beta1.Shoot
	BastionInstanceName string
	CIDRs               []string
	DiskName            string
	Zone                string
	Subnetwork          string
	ProjectID           string
	Network             string
}

// DetermineOptions determines the required information that are required to reconcile a Bastion on GCP. This
// function does not create any IaaS resources.
func DetermineOptions(bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster, projectID string) (*Options, error) {
	//Each resource name up to a maximum of 63 characters in GCP
	//https://cloud.google.com/compute/docs/naming-resources
	name := cluster.ObjectMeta.Name
	bastionInstanceName := fmt.Sprintf("%s-%s-bastion", name, bastion.Name)
	diskName := fmt.Sprintf("%s-%s-disk", name, bastion.Name)
	cidrs, err := ingressPermissions(bastion)
	if err != nil {
		return nil, err
	}

	region := cluster.Shoot.Spec.Region
	subnetwork := "regions/" + region + "/subnetworks/" + cluster.ObjectMeta.Name + "-nodes"
	zone := getZone(cluster, region)

	network := "projects/" + projectID + "/global/networks/" + cluster.ObjectMeta.Name

	return &Options{
		Shoot:               cluster.Shoot,
		BastionInstanceName: bastionInstanceName,
		Zone:                zone,
		DiskName:            diskName,
		CIDRs:               cidrs,
		Subnetwork:          subnetwork,
		ProjectID:           projectID,
		Network:             network,
	}, nil
}

func getZone(cluster *extensions.Cluster, region string) string {
	for _, j := range cluster.CloudProfile.Spec.Regions {
		if j.Name == region {
			return j.Zones[0].Name
		}
	}
	return ""
}

func ingressPermissions(bastion *extensionsv1alpha1.Bastion) ([]string, error) {
	var cidrs []string
	for _, ingress := range bastion.Spec.Ingress {
		cidr := ingress.IPBlock.CIDR
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("%w, invalid ingress CIDR %q", err, cidr)
		}

		normalisedCIDR := ipNet.String()

		if ip.To4() != nil {
			cidrs = append(cidrs, normalisedCIDR)
		} else if ip.To16() != nil {
			// Only IPv4 is supported in sourceRanges[].
			// https://cloud.google.com/compute/docs/reference/rest/v1/firewalls/insert
			return nil, fmt.Errorf("%w, IPv6 is currently not fully supported", err)
		}

	}

	return cidrs, nil
}
