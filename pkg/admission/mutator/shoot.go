// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package mutator

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// NewShootMutator returns a new instance of a shoot mutator.
func NewShootMutator(mgr manager.Manager) extensionswebhook.Mutator {
	return &shoot{
		decoder: serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
	}
}

type shoot struct {
	decoder runtime.Decoder
}

const (
	overlayKey = "overlay"
	enabledKey = "enabled"
)

// Mutate mutates the given shoot object.
func (s *shoot) Mutate(_ context.Context, new, old client.Object) error {

	shoot, ok := new.(*gardencorev1beta1.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", new)
	}

	// Skip if shoot is in restore or migration phase
	if wasShootRescheduledToNewSeed(shoot) {
		return nil
	}

	var oldShoot *gardencorev1beta1.Shoot
	if old != nil {
		oldShoot, ok = old.(*gardencorev1beta1.Shoot)
		if !ok {
			return fmt.Errorf("wrong object type %T", old)
		}
	}

	if oldShoot != nil && isShootInMigrationOrRestorePhase(shoot) {
		return nil
	}
	// Skip if specs are matching
	if oldShoot != nil && reflect.DeepEqual(shoot.Spec, oldShoot.Spec) {
		return nil
	}

	// Skip if it's a workerless Shoot
	if gardencorev1beta1helper.IsWorkerless(shoot) {
		return nil
	}

	// Skip if shoot is in deletion phase
	if shoot.DeletionTimestamp != nil || oldShoot != nil && oldShoot.DeletionTimestamp != nil {
		return nil
	}

	if shoot.Spec.Networking != nil {
		networkConfig, err := s.decodeNetworkConfig(shoot.Spec.Networking.ProviderConfig)
		if err != nil {
			return err
		}

		if oldShoot == nil && networkConfig[overlayKey] == nil {
			networkConfig[overlayKey] = map[string]interface{}{enabledKey: false}
		}

		if oldShoot != nil && networkConfig[overlayKey] == nil {
			oldNetworkConfig, err := s.decodeNetworkConfig(oldShoot.Spec.Networking.ProviderConfig)
			if err != nil {
				return err
			}

			if oldNetworkConfig[overlayKey] != nil {
				networkConfig[overlayKey] = oldNetworkConfig[overlayKey]
			}
		}

		modifiedJSON, err := json.Marshal(networkConfig)
		if err != nil {
			return err
		}
		shoot.Spec.Networking.ProviderConfig = &runtime.RawExtension{
			Raw: modifiedJSON,
		}
	}

	return nil
}

func (s *shoot) decodeNetworkConfig(network *runtime.RawExtension) (map[string]interface{}, error) {
	var networkConfig map[string]interface{}
	if network == nil || network.Raw == nil {
		return map[string]interface{}{}, nil
	}
	if err := json.Unmarshal(network.Raw, &networkConfig); err != nil {
		return nil, err
	}
	return networkConfig, nil
}

// wasShootRescheduledToNewSeed returns true if the shoot.Spec.SeedName has been changed, but the migration operation has not started yet.
func wasShootRescheduledToNewSeed(shoot *gardencorev1beta1.Shoot) bool {
	return shoot.Status.LastOperation != nil &&
		shoot.Status.LastOperation.Type != gardencorev1beta1.LastOperationTypeMigrate &&
		shoot.Spec.SeedName != nil &&
		shoot.Status.SeedName != nil &&
		*shoot.Spec.SeedName != *shoot.Status.SeedName
}

// isShootInMigrationOrRestorePhase returns true if the shoot is currently being migrated or restored.
func isShootInMigrationOrRestorePhase(shoot *gardencorev1beta1.Shoot) bool {
	return shoot.Status.LastOperation != nil &&
		(shoot.Status.LastOperation.Type == gardencorev1beta1.LastOperationTypeRestore &&
			shoot.Status.LastOperation.State != gardencorev1beta1.LastOperationStateSucceeded ||
			shoot.Status.LastOperation.Type == gardencorev1beta1.LastOperationTypeMigrate)
}
