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
	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	corev1 "k8s.io/api/core/v1"
)

// Options contains provider-related information required for setting up
// a bastion instance. This struct combines precomputed values like the
// bastion instance name with the IDs of pre-existing cloud provider
// resources, like the Firewall name, subnet name etc.
type Options struct {
	Shoot               *gardencorev1beta1.Shoot
	BastionInstanceName string
	FirewallName        string
	PublicIP            string
	DiskName            string
	Zone                string
	Region              string
	Subnetwork          string
	ProjectID           string
}

// DetermineOptions determines the required information that are required to reconcile a Bastion on GCP. This
// function does not create any IaaS resources.
func DetermineOptions(ctx context.Context, bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster) (*Options, error) {
	name := cluster.ObjectMeta.Name
	bastionInstanceName := fmt.Sprintf("%s-%s-bastion", name, bastion.Name)
	firewallName := fmt.Sprintf("%s-allow-ssh-access", bastionInstanceName)
	diskName := fmt.Sprintf("%s-%s-disk", name, bastion.Name)
	publicIP := bastion.Spec.Ingress[0].IPBlock.CIDR
	region := cluster.Shoot.Spec.Region
	subnetwork := cluster.Shoot.Name + "-nodes"
	zone := getZone(cluster, region)

	secret := &corev1.Secret{}
	serviceAccountJSON, ok := secret.Data[gcp.ServiceAccountJSONField]
	if !ok {
		return nil, fmt.Errorf("missing %q field in secret", gcp.ServiceAccountJSONField)
	}

	projectID, err := gcp.ExtractServiceAccountProjectID(serviceAccountJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to extract project id from service account: %w", err)
	}

	return &Options{
		Shoot:               cluster.Shoot,
		BastionInstanceName: bastionInstanceName,
		FirewallName:        firewallName,
		Region:              region,
		Zone:                zone,
		DiskName:            diskName,
		PublicIP:            publicIP,
		Subnetwork:          subnetwork,
		ProjectID:           projectID,
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
