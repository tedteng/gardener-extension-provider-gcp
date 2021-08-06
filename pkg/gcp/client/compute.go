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

	"github.com/gardener/gardener-extension-provider-gcp/pkg/gcp"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

// type ComputeClient struct {
// 	FirewallsClient *compute.FirewallsService
// 	// CallOptions *FirewallsCallOptions
// }

type Client struct {
	FirewallsClient *compute.FirewallsService
	DisksClient     *compute.DisksService
	InstanceClient  *compute.InstancesService
}

func NewGCPClient(ctx context.Context, serviceAccount *gcp.ServiceAccount) (*Client, error) {
	computeService, err := compute.NewService(ctx, option.WithCredentialsJSON(serviceAccount.Raw))
	if err != nil {
		return nil, err
	}

	return &Client{
		FirewallsClient: computeService.Firewalls,
		InstanceClient:  computeService.Instances,
	}, nil
}
