// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	ClientSet     *kubernetes.Clientset
	Config        *rest.Config
	DynamicClient *dynamic.DynamicClient
)

func InitClient(kubeconfigPath string) error {
	var err error

	Config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return err
	}

	ClientSet, err = kubernetes.NewForConfig(Config)
	if err != nil {
		return err
	}

	DynamicClient, err = dynamic.NewForConfig(Config)
	if err != nil {
		return err
	}

	return nil
}
