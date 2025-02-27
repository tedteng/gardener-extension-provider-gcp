// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package v1alpha1

import (
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

// SetDefaults_MachineImageVersion set the architecture of machine image.
func SetDefaults_MachineImageVersion(obj *MachineImageVersion) {
	if obj.Architecture == nil {
		obj.Architecture = pointer.String(v1beta1constants.ArchitectureAMD64)
	}
}

// SetDefaults_Storage sets the defaults for the managed storage classes
func SetDefaults_Storage(obj *Storage) {
	if obj.ManagedDefaultStorageClass == nil {
		obj.ManagedDefaultStorageClass = pointer.Bool(true)
	}
	if obj.ManagedDefaultVolumeSnapshotClass == nil {
		obj.ManagedDefaultVolumeSnapshotClass = pointer.Bool(true)
	}
}
