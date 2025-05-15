#!/bin/bash

docker save kubearmor/kubearmor-operator:latest | sudo k3s ctr images import -
docker save kubearmor/kubearmor-controller:latest | sudo k3s ctr images import -
docker save kubearmor/kubearmor:latest | sudo k3s ctr images import -
docker save kubearmor/kubearmor-init:latest | sudo k3s ctr images import -


helm upgrade --install kubearmor-operator ./deployments/helm/KubeArmorOperator -n kubearmor --create-namespace --set kubearmorOperator.image.tag=latest --set kubearmorOperator.annotateExisting=true  

kubectl apply -f pkg/KubeArmorOperator/config/samples/kubearmor-test.yaml
