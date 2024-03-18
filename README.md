# How to securely store credentials and secrets in K8s using Hashicorp Vault

This tutorial explains how to use `hashicorp vault` to securely store and inject credentials and secrets in k8s.

Steps taken during this tutorial:
1. Param value initialization
2. TLS Credentials generation
3. Deployment of `hashicorp vault` using its helm chart and customized values
4. Initialization of the `Vault` cluster
5. Enabling key-value secrets in vault and creating an example one.
6. Configuring Kubernetes authentication
7. Creating a vault role and policy for secret access
8. an example yaml file to inject the secret
9. testing

***
## Step 1. Param value initialization
adjust these values as your desire
```
export VAULT_K8S_NAMESPACE="vault" 
export VAULT_HELM_RELEASE_NAME="vault" 
export VAULT_SERVICE_NAME="vault-internal" 
export K8S_CLUSTER_NAME="mycluster" 
export WORKDIR=$(pwd)
```

***
## Step 2. TLS Credentials generation

Generate a private key
```
openssl genrsa -out ${WORKDIR}/vault.key 2048
```

Create the CSR configuration file 
```
cat > g${WORKDIR}/vault-csr.conf <<EOF
[req]
default_bits = 2048
prompt = no
encrypt_key = yes
default_md = sha256
distinguished_name = kubelet_serving
req_extensions = v3_req
[ kubelet_serving ]
O = system:nodes
CN = system:node:*.${VAULT_K8S_NAMESPACE}.svc.${K8S_CLUSTER_NAME}
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = *.${VAULT_SERVICE_NAME}
DNS.2 = *.${VAULT_SERVICE_NAME}.${VAULT_K8S_NAMESPACE}.svc.${K8S_CLUSTER_NAME}
DNS.3 = *.${VAULT_K8S_NAMESPACE}
IP.1 = 127.0.0.1
EOF
```

3.4. create request
openssl req -new -key ${WORKDIR}/vault.key -out ${WORKDIR}/vault.csr -config ${WORKDIR}/vault-csr.conf

3.5. Create the csr yaml file to send it to Kubernetes.
> cat > ${WORKDIR}/csr.yaml <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
   name: vault.svc
spec:
   signerName: kubernetes.io/kubelet-serving
   expirationSeconds: 8640000
   request: $(cat ${WORKDIR}/vault.csr|base64|tr -d '\n')
   usages:
   - digital signature
   - key encipherment
   - server auth
EOF

> kubectl create -f ${WORKDIR}/csr.yaml
> kubectl certificate approve vault.svc

3.6. Store the certificates and Key in the Kubernetes secrets store
> kubectl get csr vault.svc -o jsonpath='{.status.certificate}' | openssl base64 -d -A -out ${WORKDIR}/vault.crt

3.7. Retrieve Kubernetes CA certificate
> kubectl config view \
--raw \
--minify \
--flatten \
-o jsonpath='{.clusters[].cluster.certificate-authority-data}' \
| base64 -d > ${WORKDIR}/vault.ca


3.8. create TLS Secret
> kubectl create secret generic vault-ha-tls \
-n $VAULT_K8S_NAMESPACE \
--from-file=vault.key=${WORKDIR}/vault.key \
--from-file=vault.crt=${WORKDIR}/vault.crt \
--from-file=vault.ca=${WORKDIR}/vault.ca

************************************************************
4. install vault (helm search repo vault --versions)
************************************************************

2.2. kubectl create namespace $VAULT_K8S_NAMESPACE
1. helm repo add hashicorp https://helm.releases.hashicorp.com
-----
vault-values.yaml file:
cat > ${WORKDIR}/vault-values.yaml <<EOF
global:
   enabled: true
   tlsDisable: false
injector:
   enabled: true
server:
   extraEnvironmentVars:
      VAULT_CACERT: /vault/userconfig/vault-ha-tls/vault.ca
      VAULT_TLSCERT: /vault/userconfig/vault-ha-tls/vault.crt
      VAULT_TLSKEY: /vault/userconfig/vault-ha-tls/vault.key
   volumes:
      - name: userconfig-vault-ha-tls
        secret:
         defaultMode: 420
         secretName: vault-ha-tls
   volumeMounts:
      - mountPath: /vault/userconfig/vault-ha-tls
        name: userconfig-vault-ha-tls
        readOnly: true
   standalone:
      enabled: false
   affinity: ""
   ha:
      enabled: true
      replicas: 3
      raft:
         enabled: true
         setNodeId: true
         config: |
            ui = true
            listener "tcp" {
               tls_disable = 0
               address = "[::]:8200"
               cluster_address = "[::]:8201"
               tls_cert_file = "/vault/userconfig/vault-ha-tls/vault.crt"
               tls_key_file  = "/vault/userconfig/vault-ha-tls/vault.key"
               tls_client_ca_file = "/vault/userconfig/vault-ha-tls/vault.ca"
            }
            storage "raft" {
               path = "/vault/data"
            }
            disable_mlock = true
            service_registration "kubernetes" {}
EOF
-----
> helm install -n $VAULT_K8S_NAMESPACE $VAULT_HELM_RELEASE_NAME hashicorp/vault -f ${WORKDIR}/vault-values.yaml
> kubectl -n $VAULT_K8S_NAMESPACE get pods (you should see three vaults including vault-0, vault-1 and vault-2)
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault status # you see all vaults are sealed.

6. Initialize and unseal one Vault pod
> kubectl exec -n $VAULT_K8S_NAMESPACE vault-0 -- vault operator init \
    -key-shares=3 \
    -key-threshold=3 \
    -format=json > ${WORKDIR}/cluster-keys.json

*** -key-shares=3 is the number of keys to generate
    -key-threshold=3 is the minimum number of keys to unseal a vault pod.

> cat cluster-keys.json | jq -r ".unseal_keys_b64[]"  # retrieve keys. You need to edit these linee. they are for one key
> VAULT_UNSEAL_KEY1=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[0]") \
  VAULT_UNSEAL_KEY2=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[1]") \
  VAULT_UNSEAL_KEY3=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[2]")
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY1  # do not use this approach. it will save the key to the history of the linux.
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY2
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY3

# add the other vaults to the vault cluster
> cat cluster-keys.json | jq -r ".root_token"  # retrieve the token.
> CLUSTER_ROOT_TOKEN=$(cat cluster-keys.json | jq -r ".root_token")
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault login $CLUSTER_ROOT_TOKEN
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator raft list-peers # see peers
# > kubectl -n $VAULT_K8S_NAMESPACE exec vault-1 -- vault operator raft join http://vault-0.vault-internal:8200
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-1 -- vault operator raft join -address=https://vault-1.vault-internal:8200 -leader-ca-cert="$(cat vault.ca)" -leader-client-cert="$(cat vault.crt)" -leader-client-key="$(cat vault.key)" https://vault-0.vault-internal:8200
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-1 -- vault operator unseal $VAULT_UNSEAL_KEY1 
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-1 -- vault operator unseal $VAULT_UNSEAL_KEY2 
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-1 -- vault operator unseal $VAULT_UNSEAL_KEY3
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-2 -- vault operator raft join -address=https://vault-2.vault-internal:8200 -leader-ca-cert="$(cat vault.ca)" -leader-client-cert="$(cat vault.crt)" -leader-client-key="$(cat vault.key)" https://vault-0.vault-internal:8200
# > kubectl -n $VAULT_K8S_NAMESPACE exec vault-2 -- vault operator raft join http://vault-0.vault-internal:8200 # for without TLS
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-2 -- vault operator unseal $VAULT_UNSEAL_KEY1
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-2 -- vault operator unseal $VAULT_UNSEAL_KEY2
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-2 -- vault operator unseal $VAULT_UNSEAL_KEY3
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator raft list-peers
> kubectl -n $VAULT_K8S_NAMESPACE get pods

************************************************************
7.1. write secrets:
************************************************************
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault secrets enable -path=credentials kv-v2
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault kv put credentials/keyValue/dbUserPass username="db-readonly-username" password="db-secret-password"
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault kv get credentials/keyValue/dbUserPass
7.2. get secret by Curl
> kubectl -n $VAULT_K8S_NAMESPACE port-forward service/vault 8200:8200 > /dev/null 2>&1 & 
> curl --cacert $WORKDIR/vault.ca    --header "X-Vault-Token: $CLUSTER_ROOT_TOKEN"    https://127.0.0.1:8200/v1/internal/data/database/config | jq .data.data

************************************************************
8. Configure Kubernetes authentication
************************************************************
> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault auth enable kubernetes

> token_reviewer=$(kubectl -n $VAULT_K8S_NAMESPACE -it exec vault-0 -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
> KUBERNETES_PORT_443_TCP_ADDR="$(kubectl -n $VAULT_K8S_NAMESPACE -it exec vault-0 -- env | grep KUBERNETES_PORT_443_TCP_ADDR | cut -d = -f2)"
> KUBERNETES_PORT_443_TCP_ADDR=$(echo ${KUBERNETES_PORT_443_TCP_ADDR:0:-1})    # to remove '$'r' from its end.

# following command makes vault able to communicate with kubernetes api
>  kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault write auth/kubernetes/config \
> token_reviewer_jwt="$token_reviewer" \
> kubernetes_host="https://${KUBERNETES_PORT_443_TCP_ADDR}:443" \
> kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

*** KUBERNETES_PORT_443_TCP_ADDR is defined and references the internal network address of the Kubernetes host
    token_reviewer: Vault uses this token to authenticate itself when making calls with the Kubernetes API

************************************************************
9. #Create a role for our app to access secrets
************************************************************

> kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault write auth/kubernetes/role/secret-role \
bound_service_account_names=vault-credentials-service-account \
bound_service_account_namespaces=test-ns \
policies=vault-credentials-read-policy \
ttl=1h


> kubectl -n vault exec vault-0 -- sh -c "cat <<EOF > /home/vault/vault-policy.hcl
path \"credentials/data/keyValue/*\" {
  capabilities = ["read"]
}
EOF"

> kubectl -n vault exec vault-0 -- vault policy write vault-credentials-read-policy /home/vault/vault-policy.hcl



> cat > test-app.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  labels:
    app: vault-test
spec:
  selector:
    matchLabels:
      app: test-app
  replicas: 1
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/tls-skip-verify: "true"
        vault.hashicorp.com/agent-inject-status: 'update'
        vault.hashicorp.com/agent-inject-secret-dbUserPass.txt: "credentials/keyValue/dbUserPass"
        vault.hashicorp.com/agent-inject-template-dbUserPass.txt: |
          {{- with secret "credentials/keyValue/dbUserPass" -}}
          {
            "username" : "{{ .Data.data.username }}",
            "password" : "{{ .Data.data.password }}"
          }
          {{- end }}
        vault.hashicorp.com/role: "secret-role"
      labels:
        app: test-app
    spec:
      serviceAccountName: vault-credentials-service-account
      containers:
      - name: test-app
        image: jweissig/app:0.0.1
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-credentials-service-account
  labels:
    app: vault-test
EOF


*** agent-inject-secret-dbUserPasss.txt: agent-inject-secret is prefix and dbUserPasss.txt will be the name of the injected secret to /vault/secrets
*** agent-inject-status: 'update' to update if we changed.

> kube create ns test-ns
> kubectl -n test-ns apply --filename test-app.yaml

> kubectl -n test-ns patch deployment test-app
 --patch "$(cat test-app.yaml)"  # use patch whenever you edit the yaml file. this way a new pod as "test-app" will be created and when completed, it will replace the old one.

# Display the secrets written to the file /vault/secrets/dbUserPass on the test-app pod.
> kubectl -n test-ns exec --stdin=true --tty=true $(kubectl -n test-ns get pod | grep test-app | cut -d " " -f1) --container test-app -- cat /vault/secrets/dbuserpass.txt

output is as following:
{
   "username" : username,
   "password" : password
}

