// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package client

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
)

const (
	// SSHPort is the default SSH Port used for bastion ingress firewall rule
	SSHPort                 = 22
	errCodeFirewallNotFound = 404
	errCodeFirewallExists   = 409
)

var logger logr.Logger

// type Firewall interface {
// 	FirewallCreate(ctx context.Context, projectID string, rb *compute.Firewall) error
// }

func (c *Client) FirewallGet(ctx context.Context, projectID, firewallRuleName string) (*compute.Firewall, error) {
	firewall, err := c.FirewallsClient.Get(projectID, firewallRuleName).Context(ctx).Do()
	if err != nil {
		if googleError, ok := err.(*googleapi.Error); ok && googleError.Code == errCodeFirewallNotFound {
			logger.Info("Firewall rule not found,", "firewall_rule_name", firewallRuleName)
			return nil, nil
		}
		return nil, err
	}
	return firewall, nil
}

func (c *Client) FirewallCreate(ctx context.Context, projectID string, rb *compute.Firewall) error {
	if _, err := c.FirewallsClient.Insert(projectID, rb).Context(ctx).Do(); err != nil {
		if googleError, ok := err.(*googleapi.Error); ok && googleError.Code == errCodeFirewallExists {
			logger.Info("Firewall rule already exits,", "firewall_rule_name", rb.Name)
			return nil
		}
		return fmt.Errorf("%w, could not create firewall rule %s", err, rb.Name)
	}

	logger.Info("Firewall created", "firewall", rb.Name)
	return nil
}

func (c *Client) FirewallPatch(ctx context.Context, projectID string, firewallRuleName string, rb *compute.Firewall) error {
	if _, err := c.FirewallsClient.Patch(projectID, firewallRuleName, rb).Context(ctx).Do(); err != nil {
		if googleError, ok := err.(*googleapi.Error); ok && googleError.Code == errCodeFirewallExists {
			logger.Info("Firewall rule already exits,", "firewall_rule_name", rb.Name)
			return nil
		}
		return fmt.Errorf("%w, could not create firewall rule %s", err, rb.Name)
	}

	logger.Info("Firewall created", "firewall", rb.Name)
	return nil
}
