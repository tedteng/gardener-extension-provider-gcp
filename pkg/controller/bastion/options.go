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
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net"

	"github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
)

//Maximum length for "base" name due to fact that we use this name to name other GCP resources,
//and it's required to fit 63 character length https://cloud.google.com/compute/docs/naming-resources
const maxLengthForBastionBaseName = 33
const maxLengthForResource = 63

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

type ProviderStatusRaw struct {
	BastionComputeInstanceName string `json:"bastionComputeInstanceName"`
	Zone                       string `json:"zone"`
}

// DetermineOptions determines the required information that are required to reconcile a Bastion on GCP. This
// function does not create any IaaS resources.
func DetermineOptions(bastion *extensionsv1alpha1.Bastion, cluster *controller.Cluster, projectID string) (*Options, error) {
	//Each resource name up to a maximum of 63 characters in GCP
	//https://cloud.google.com/compute/docs/naming-resources
	clusterName := cluster.ObjectMeta.Name

	providerStatus, err := getProviderStatus(bastion)
	if err != nil {
		return nil, err
	}

	bastionComputeInstanceName, err := getBastionComputeInstanceName(clusterName, bastion.Name, providerStatus)
	if err != nil {
		return nil, err
	}

	diskName := checkCreateNewResourceName(clusterName, bastion.Name, "disk")
	cidrs, err := ingressPermissions(bastion)
	if err != nil {
		return nil, err
	}

	region := cluster.Shoot.Spec.Region
	subnetwork := fmt.Sprintf("regions/%s/subnetworks/%s", region, checkCreateNewResourceName(clusterName, "", "nodes"))
	zone := getZone(cluster, region, providerStatus)
	network := fmt.Sprintf("projects/%s/global/networks/%s", projectID, checkCreateNewResourceName(clusterName, "", ""))

	return &Options{
		Shoot:               cluster.Shoot,
		BastionInstanceName: bastionComputeInstanceName,
		Zone:                zone,
		DiskName:            diskName,
		CIDRs:               cidrs,
		Subnetwork:          subnetwork,
		ProjectID:           projectID,
		Network:             network,
	}, nil
}

func getZone(cluster *extensions.Cluster, region string, providerStatus *ProviderStatusRaw) string {
	if providerStatus != nil {
		return providerStatus.Zone
	}

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

func getBastionComputeInstanceName(clusterName string, bastionName string, providerStatus *ProviderStatusRaw) (string, error) {
	if providerStatus != nil {
		return providerStatus.BastionComputeInstanceName, nil
	}
	return generateBastionBaseResourceName(clusterName, bastionName)
}

func checkCreateNewResourceName(clusterName string, bastionName string, resourceTypeName string) string {
	tempBase := clusterName
	if len(bastionName) > 0 {
		tempBase = fmt.Sprintf("%s-%s", clusterName, bastionName)
	}
	if len([]rune(tempBase)) > maxLengthForResource {
		tempBase = tempBase[:maxLengthForResource]
	}
	if len(resourceTypeName) > 0 {
		if len([]rune(tempBase)) > (maxLengthForResource - len(resourceTypeName) - 1) {
			tempBase = fmt.Sprintf("%s-%s", tempBase[:maxLengthForResource-len(resourceTypeName)-1], resourceTypeName)
		}
		tempBase = fmt.Sprintf("%s-%s", tempBase, resourceTypeName)
	}
	return tempBase
}

func generateBastionBaseResourceName(clusterName string, bastionName string) (string, error) {
	staticName := clusterName + "-" + bastionName
	hashName := b64.StdEncoding.EncodeToString([]byte(staticName))
	if len([]rune(staticName)) > maxLengthForBastionBaseName {
		staticName = staticName[:maxLengthForBastionBaseName]
	}
	return fmt.Sprintf("%s-bastion-%s", staticName, hashName[:5]), nil
}

func getProviderStatus(bastion *extensionsv1alpha1.Bastion) (*ProviderStatusRaw, error) {
	if bastion.Status.ProviderStatus != nil && bastion.Status.ProviderStatus.Raw != nil {
		return unmarshalProviderStatus(bastion.Status.ProviderStatus.Raw)
	}
	return nil, nil
}

func marshalProvideStatus(zone string, bastionComputeInstanceName string) ([]byte, error) {
	return json.Marshal(&ProviderStatusRaw{
		BastionComputeInstanceName: bastionComputeInstanceName,
		Zone:                       zone,
	})
}

func unmarshalProviderStatus(bytes []byte) (*ProviderStatusRaw, error) {
	info := &ProviderStatusRaw{}

	err := json.Unmarshal(bytes, info)
	if err != nil {
		return nil, fmt.Errorf("failed to parse json for status.ProviderStatus")
	}
	return info, nil
}
