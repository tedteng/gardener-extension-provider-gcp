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
	"strconv"

	"google.golang.org/api/compute/v1"
)

func ingressAllowSSH(opt *Options) *compute.Firewall {
	return &compute.Firewall{
		Allowed:      []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{strconv.Itoa(SSHPort)}}},
		Description:  "SSH access for Bastion",
		Direction:    "INGRESS",
		TargetTags:   []string{opt.BastionInstanceName},
		Name:         firewallIngressAllowSSHResourceName(opt.BastionInstanceName),
		Network:      opt.Network,
		SourceRanges: opt.CIDRs,
		Priority:     50,
	}
}

func egressDenyAll(opt *Options) *compute.Firewall {
	return &compute.Firewall{
		Denied:            []*compute.FirewallDenied{{IPProtocol: "all"}},
		Description:       "Bastion egress deny",
		Direction:         "EGRESS",
		TargetTags:        []string{opt.BastionInstanceName},
		Name:              firewallEgressDenyAllResourceName(opt.BastionInstanceName),
		Network:           opt.Network,
		DestinationRanges: []string{"0.0.0.0/0"},
		Priority:          1000,
	}
}

func egressAllowOnly(opt *Options) *compute.Firewall {
	return &compute.Firewall{
		Allowed:           []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{strconv.Itoa(SSHPort)}}},
		Description:       "Allow Bastion egress to Shoot workers",
		Direction:         "EGRESS",
		TargetTags:        []string{opt.BastionInstanceName},
		Name:              firewallEgressAllowOnlyResourceName(opt.BastionInstanceName),
		Network:           opt.Network,
		DestinationRanges: []string{opt.WorkersCIDR},
		Priority:          60,
	}
}

func patchCIDRs(opt *Options) *compute.Firewall {
	return &compute.Firewall{SourceRanges: opt.CIDRs}
}
