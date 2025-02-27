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

package client

import (
	"context"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/gardener/gardener-extension-provider-gcp/pkg/gcp"
)

// ComputeClient is the interface for a GCP Compute API client that can perform all operations needed for the provider-extension.
type ComputeClient interface {
	// GetExternalAddresses returns a list of all external IP addresses mapped to the names of their users.
	GetExternalAddresses(ctx context.Context, region string) (map[string][]string, error)
	// GetAddress returns a Address.
	GetAddress(ctx context.Context, region, name string) (*Address, error)

	// InsertNetwork creates a Network with the given specification.
	InsertNetwork(ctx context.Context, nw *Network) (*Network, error)
	// GetNetwork reads provider information for the specified Network.
	GetNetwork(ctx context.Context, id string) (*Network, error)
	// DeleteNetwork deletes the Network. Return no error if the network is not found
	DeleteNetwork(ctx context.Context, id string) error
	// PatchNetwork patches the network identified by id with the given specification.
	PatchNetwork(ctx context.Context, id string, nw *Network) (*Network, error)

	// InsertSubnet creates a Subnetwork with the given specification.
	InsertSubnet(ctx context.Context, region string, subnet *Subnetwork) (*Subnetwork, error)
	// GetSubnet returns the Subnetwork specified by id.
	GetSubnet(ctx context.Context, region, id string) (*Subnetwork, error)
	// PatchSubnet updates the Subnetwork specified by id with the given specification.
	PatchSubnet(ctx context.Context, region, id string, subnet *Subnetwork) (*Subnetwork, error)
	// DeleteSubnet deletes the Subnetwork specified by id.
	DeleteSubnet(ctx context.Context, region, id string) error
	// ExpandSubnet expands the subnet to the target CIDR.
	ExpandSubnet(ctx context.Context, region, id, cidr string) (*Subnetwork, error)

	// InsertRouter creates a router with the given specification.
	InsertRouter(ctx context.Context, region string, router *Router) (*Router, error)
	// GetRouter returns the Router specified by id.
	GetRouter(ctx context.Context, region, id string) (*Router, error)
	// PatchRouter updates the Router specified by id with the given specification.
	PatchRouter(ctx context.Context, region, id string, router *Router) (*Router, error)
	// DeleteRouter deletes the router specified by id.
	DeleteRouter(ctx context.Context, region, id string) error
	// ListRoutes lists all routes.
	ListRoutes(ctx context.Context) ([]*Route, error)
	// DeleteRoute deletes the specified route.
	DeleteRoute(ctx context.Context, id string) error

	// InsertFirewallRule creates a firewall rule with the given specification.
	InsertFirewallRule(ctx context.Context, firewall *Firewall) (*Firewall, error)
	// GetFirewallRule returns the firewall rule specified by id.
	GetFirewallRule(ctx context.Context, firewall string) (*Firewall, error)
	// PatchFirewallRule updates the firewall rule specified by id with the given specification.
	PatchFirewallRule(ctx context.Context, name string, firewall *Firewall) (*Firewall, error)
	// DeleteFirewallRule deletes  the firewall rule specified by id.
	DeleteFirewallRule(ctx context.Context, firewall string) error
	// ListFirewallRules lists all firewall rules.
	ListFirewallRules(ctx context.Context) ([]*Firewall, error)
}

type computeClient struct {
	service   *compute.Service
	projectID string
}

// NewComputeClient returns a client for Compute API. The client follows the following conventions:
// Unless stated otherwise all operations are synchronous: even on operations that are asynchronous on GCP API e.g. Insert operations returning compute.Operation. The client should wait until
// the completion of the respective operations before returning.
// Delete operations will ignore errors when the respective resource can not be found, meaning that the Delete operations will never return HTTP 404 errors.
// Update operations will ignore errors when the update operation is a no-op, meaning that Update operations will ignore HTTP 304 errors.
func NewComputeClient(ctx context.Context, serviceAccount *gcp.ServiceAccount) (ComputeClient, error) {
	jwt, err := google.JWTConfigFromJSON(serviceAccount.Raw, compute.ComputeScope)
	if err != nil {
		return nil, err
	}

	httpClient := oauth2.NewClient(ctx, jwt.TokenSource(ctx))
	service, err := compute.NewService(ctx, option.WithHTTPClient(httpClient))
	if err != nil {
		return nil, err
	}

	return &computeClient{
		service:   service,
		projectID: serviceAccount.ProjectID,
	}, nil
}

// GetExternalAddresses returns a list of all external IP addresses mapped to the names of their users.
func (c *computeClient) GetExternalAddresses(ctx context.Context, region string) (map[string][]string, error) {
	addresses := make(map[string][]string)
	if err := c.service.Addresses.List(c.projectID, region).Pages(ctx, func(resp *compute.AddressList) error {
		for _, address := range resp.Items {
			if address.AddressType == "EXTERNAL" {
				var userNames []string
				if address.Status == "IN_USE" {
					for _, user := range address.Users {
						parts := strings.Split(user, "/")
						userNames = append(userNames, parts[len(parts)-1])
					}
				}
				addresses[address.Name] = userNames
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return addresses, nil
}

// InsertNetwork creates a Network with the given specification.
func (c *computeClient) InsertNetwork(ctx context.Context, n *Network) (*Network, error) {
	op, err := c.service.Networks.Insert(c.projectID, n).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	err = c.wait(ctx, op)
	if err != nil {
		return nil, err
	}
	return c.GetNetwork(ctx, n.Name)
}

// GetNetwork reads provider information for the specified Network.
func (c *computeClient) GetNetwork(ctx context.Context, id string) (*Network, error) {
	nw, err := c.service.Networks.Get(c.projectID, id).Context(ctx).Do()
	if err != nil {
		return nil, IgnoreNotFoundError(err)
	}
	return nw, err
}

// DeleteNetwork deletes the Network. Return no error if the network is not found
func (c *computeClient) DeleteNetwork(ctx context.Context, id string) error {
	op, err := c.service.Networks.Delete(c.projectID, id).Context(ctx).Do()
	if IgnoreNotFoundError(err) != nil {
		return err
	}
	if IsNotFoundError(err) {
		return nil
	}
	return c.wait(ctx, op)
}

// PatchNetwork patches the network identified by id with the given specification.
func (c *computeClient) PatchNetwork(ctx context.Context, id string, n *Network) (*Network, error) {
	op, err := c.service.Networks.Patch(c.projectID, id, n).Context(ctx).Do()
	if IgnoreErrorCodes(err, http.StatusNotModified) != nil {
		return nil, err
	}
	if IsErrorCode(err, http.StatusNotModified) {
		return n, nil
	}
	err = c.wait(ctx, op)
	if err != nil {
		return nil, err
	}

	return c.GetNetwork(ctx, n.Name)
}

// InsertSubnet creates a Subnetwork with the given specification.
func (c *computeClient) InsertSubnet(ctx context.Context, region string, subnet *Subnetwork) (*Subnetwork, error) {
	op, err := c.service.Subnetworks.Insert(c.projectID, region, subnet).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	err = c.wait(ctx, op)
	if err != nil {
		return nil, err
	}
	return c.GetSubnet(ctx, region, subnet.Name)
}

// GetSubnet returns the Subnetwork specified by id.
func (c *computeClient) GetSubnet(ctx context.Context, region, id string) (*Subnetwork, error) {
	s, err := c.service.Subnetworks.Get(c.projectID, region, id).Context(ctx).Do()
	if err != nil {
		return nil, IgnoreNotFoundError(err)
	}

	return s, nil
}

// PatchSubnet updates the Subnetwork specified by id with the given specification.
func (c *computeClient) PatchSubnet(ctx context.Context, region, id string, subnet *Subnetwork) (*Subnetwork, error) {
	op, err := c.service.Subnetworks.Patch(c.projectID, region, id, subnet).Context(ctx).Do()
	if IgnoreErrorCodes(err, http.StatusNotModified) != nil {
		return nil, err
	}
	if IsErrorCode(err, http.StatusNotModified) {
		return subnet, nil
	}
	err = c.wait(ctx, op)
	if err != nil {
		return nil, err
	}

	return c.GetSubnet(ctx, region, id)
}

// DeleteSubnet deletes the Subnetwork specified by id.
func (c *computeClient) DeleteSubnet(ctx context.Context, region, id string) error {
	op, err := c.service.Subnetworks.Delete(c.projectID, region, id).Context(ctx).Do()
	if IgnoreNotFoundError(err) != nil {
		return err
	}
	if IsNotFoundError(err) {
		return nil
	}
	return c.wait(ctx, op)
}

// ExpandSubnet expands the subnet to the target CIDR.
func (c *computeClient) ExpandSubnet(ctx context.Context, region, id, cidr string) (*Subnetwork, error) {
	op, err := c.service.Subnetworks.ExpandIpCidrRange(c.projectID, region, id, &compute.SubnetworksExpandIpCidrRangeRequest{
		IpCidrRange: cidr,
	}).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	err = c.wait(ctx, op)
	if err != nil {
		return nil, err
	}

	return c.GetSubnet(ctx, region, id)
}

// InsertRouter creates a router with the given specification.
func (c *computeClient) InsertRouter(ctx context.Context, region string, router *Router) (*Router, error) {
	op, err := c.service.Routers.Insert(c.projectID, region, router).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	err = c.wait(ctx, op)
	if err != nil {
		return nil, err
	}
	return c.GetRouter(ctx, region, router.Name)
}

// GetRouter returns the Router specified by id.
func (c *computeClient) GetRouter(ctx context.Context, region, id string) (*Router, error) {
	r, err := c.service.Routers.Get(c.projectID, region, id).Context(ctx).Do()
	if err != nil {
		return nil, IgnoreNotFoundError(err)
	}

	return r, nil
}

// PatchRouter updates the Router specified by id with the given specification.
func (c *computeClient) PatchRouter(ctx context.Context, region, id string, router *Router) (*Router, error) {
	op, err := c.service.Routers.Patch(c.projectID, region, id, router).Context(ctx).Do()
	if IgnoreErrorCodes(err, http.StatusNotModified) != nil {
		return nil, err
	}
	if IsErrorCode(err, http.StatusNotModified) {
		return router, nil
	}
	err = c.wait(ctx, op)
	if err != nil {
		return nil, err
	}

	return c.GetRouter(ctx, region, router.Name)
}

// DeleteRouter deletes the router specified by id.
func (c *computeClient) DeleteRouter(ctx context.Context, region, id string) error {
	op, err := c.service.Routers.Delete(c.projectID, region, id).Context(ctx).Do()
	if IgnoreNotFoundError(err) != nil {
		return err
	}
	if IsNotFoundError(err) {
		return nil
	}
	return c.wait(ctx, op)
}

// ListRoutes lists all routes.
func (c *computeClient) ListRoutes(ctx context.Context) ([]*Route, error) {
	routes, err := c.service.Routes.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return routes.Items, nil
}

// GetAddress returns a compute.Address.
func (c *computeClient) GetAddress(ctx context.Context, region, name string) (*Address, error) {
	a, err := c.service.Addresses.Get(c.projectID, region, name).Context(ctx).Do()
	if err != nil {
		return nil, IgnoreNotFoundError(err)
	}
	return a, nil
}

// InsertFirewallRule creates a firewall rule with the given specification.
func (c *computeClient) InsertFirewallRule(ctx context.Context, firewall *Firewall) (*Firewall, error) {
	op, err := c.service.Firewalls.Insert(c.projectID, firewall).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	err = c.wait(ctx, op)
	if err != nil {
		return nil, err
	}
	return c.GetFirewallRule(ctx, firewall.Name)
}

// GetFirewallRule returns the firewall rule specified by id.
func (c *computeClient) GetFirewallRule(ctx context.Context, firewall string) (*Firewall, error) {
	rule, err := c.service.Firewalls.Get(c.projectID, firewall).Context(ctx).Do()
	if err != nil {
		return nil, IgnoreNotFoundError(err)
	}

	return rule, nil
}

// DeleteFirewallRule deletes  the firewall rule specified by id.
func (c *computeClient) DeleteFirewallRule(ctx context.Context, firewall string) error {
	op, err := c.service.Firewalls.Delete(c.projectID, firewall).Context(ctx).Do()
	if IgnoreNotFoundError(err) != nil {
		return err
	}
	if IsNotFoundError(err) {
		return nil
	}
	return c.wait(ctx, op)
}

// PatchFirewallRule updates the firewall rule specified by id with the given specification.
func (c *computeClient) PatchFirewallRule(ctx context.Context, name string, rule *Firewall) (*Firewall, error) {
	op, err := c.service.Firewalls.Patch(c.projectID, name, rule).Context(ctx).Do()
	if IgnoreErrorCodes(err, http.StatusNotModified) != nil {
		return nil, err
	}
	if IsErrorCode(err, http.StatusNotModified) {
		return rule, nil
	}
	err = c.wait(ctx, op)
	if err != nil {
		return nil, err
	}

	return c.GetFirewallRule(ctx, name)
}

// ListFirewallRules lists all firewall rules.
func (c *computeClient) ListFirewallRules(ctx context.Context) ([]*Firewall, error) {
	fws, err := c.service.Firewalls.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	return fws.Items, nil
}

// DeleteRoute deletes the specified route.
func (c *computeClient) DeleteRoute(ctx context.Context, name string) error {
	op, err := c.service.Routes.Delete(c.projectID, name).Context(ctx).Do()
	if IgnoreNotFoundError(err) != nil {
		return err
	}
	if err != nil {
		return err
	}

	return c.wait(ctx, op)
}
