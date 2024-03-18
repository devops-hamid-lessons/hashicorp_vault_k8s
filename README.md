# How to securely store credentials and secrets in K8s using Hashicorp Vault

This tutorial explains how to use `hashicorp vault` to securely store and inject credentials and secrets in k8s.

Steps taken during this tutorial:
1. Param value initialization
2. TLS Credentials generation
3. Deployment of `hashicorp vault` using its helm chart and customized values
4. Initialization of the `Vault` cluster
5. Enabling key-value secrets in vault and creating an example one.
6. Configuring Kubernetes authentication
7. Creating a vault role and a policy for secret access
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

Generate a private key -> this will generate `vault.key` file
```
openssl genrsa -out ${WORKDIR}/vault.key 2048
```

Create the CSR configuration file (CSR = Certificate Signing Request) 
```
cat > ${WORKDIR}/vault-csr.conf <<EOF
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

Create the request -> this will generate `vault.csr` file.
```
openssl req -new -key ${WORKDIR}/vault.key -out ${WORKDIR}/vault.csr -config ${WORKDIR}/vault-csr.conf
```

Now we need to send the generated `vault.csr` file to k8s to sign it.
Create following k8s CSR yaml file using the generated `vault.csr` in the previous step to send it to kubernetes. kubernetes will sign it using its own private key.
```
cat > ${WORKDIR}/csr.yaml <<EOF
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
```
```
kubectl create -f ${WORKDIR}/csr.yaml
```

This will generate the certificate, but you need to approve it as below:
```
kubectl certificate approve vault.svc
```

Now we need to extract the  generated certificate.
Command below extracts and stores it in `vault.crt`
```
kubectl get csr vault.svc -o jsonpath='{.status.certificate}' | openssl base64 -d -A -out ${WORKDIR}/vault.crt
```

For TLS communication, we also need to Retrieve the kubernetes CA certificate. To do so, use command below to store it in `vault.ca` file.
```
kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}' | base64 -d > ${WORKDIR}/vault.ca
```


As the final step of TLS cert generation, create a TLS Secret including `vault.key`, `vault.crt`, and `vault.ca`
```
kubectl create secret generic vault-ha-tls \
-n $VAULT_K8S_NAMESPACE \
--from-file=vault.key=${WORKDIR}/vault.key \
--from-file=vault.crt=${WORKDIR}/vault.crt \
--from-file=vault.ca=${WORKDIR}/vault.ca
```

***
## Step 3. Deployment of `hashicorp vault`

```
kubectl create namespace $VAULT_K8S_NAMESPACE
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install -n $VAULT_K8S_NAMESPACE $VAULT_HELM_RELEASE_NAME hashicorp/vault -f ${WORKDIR}/vault-values.yaml
```
Refer to vault-values.yaml for the customized values like replica count. You can change then as your requirements.

Test installation
```
kubectl -n $VAULT_K8S_NAMESPACE get pods # By my values, you should see three vaults including vault-0, vault-1 and vault-2 
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault status # you see all vaults are sealed.
```

***
Step 4. Initialization of the `Vault` cluster
Initialize master vault pod (vault-0)
```
kubectl exec -n $VAULT_K8S_NAMESPACE vault-0 -- vault operator init \
    -key-shares=3 \
    -key-threshold=3 \
    -format=json > ${WORKDIR}/cluster-keys.json
```
* Command above will generate `unsealing keys` + a vault login token and store them in cluster-keys.json file.
* -key-shares=3 is the number of unsealing keys to generate 
* -key-threshold=3 is the minimum number of unsealing keys required to unseal a vault pod.


Retrieve unsealing keys
```
VAULT_UNSEAL_KEY1=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[0]") 
VAULT_UNSEAL_KEY2=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[1]") 
VAULT_UNSEAL_KEY3=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[2]")
```

Unseal master vault pod (vault-0)
```
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY1  # Preferably, do not use this approach. it will save the key to the history of the linux.
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY2
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator unseal $VAULT_UNSEAL_KEY3
```

Add the other vault pods to the vault cluster and unseal them
```
CLUSTER_ROOT_TOKEN=$(cat cluster-keys.json | jq -r ".root_token") # retrieve the vault login token.
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault login $CLUSTER_ROOT_TOKEN
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator raft list-peers # You will see no peers
kubectl -n $VAULT_K8S_NAMESPACE exec vault-1 -- vault operator raft join -address=https://vault-1.vault-internal:8200 -leader-ca-cert="$(cat vault.ca)" -leader-client-cert="$(cat vault.crt)" -leader-client-key="$(cat vault.key)" https://vault-0.vault-internal:8200
kubectl -n $VAULT_K8S_NAMESPACE exec vault-1 -- vault operator unseal $VAULT_UNSEAL_KEY1 
kubectl -n $VAULT_K8S_NAMESPACE exec vault-1 -- vault operator unseal $VAULT_UNSEAL_KEY2 
kubectl -n $VAULT_K8S_NAMESPACE exec vault-1 -- vault operator unseal $VAULT_UNSEAL_KEY3
kubectl -n $VAULT_K8S_NAMESPACE exec vault-2 -- vault operator raft join -address=https://vault-2.vault-internal:8200 -leader-ca-cert="$(cat vault.ca)" -leader-client-cert="$(cat vault.crt)" -leader-client-key="$(cat vault.key)" https://vault-0.vault-internal:8200
kubectl -n $VAULT_K8S_NAMESPACE exec vault-2 -- vault operator unseal $VAULT_UNSEAL_KEY1
kubectl -n $VAULT_K8S_NAMESPACE exec vault-2 -- vault operator unseal $VAULT_UNSEAL_KEY2
kubectl -n $VAULT_K8S_NAMESPACE exec vault-2 -- vault operator unseal $VAULT_UNSEAL_KEY3
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault operator raft list-peers  # Now You will see vault-1 and vault-2 as peers
```
***
## Step 5. Enabling key-value secrets in vault and creating an example one.
```
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault secrets enable -path=credentials kv-v2
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault kv put credentials/keyValue/dbUserPass username="db-readonly-username" password="db-secret-password"
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault kv get credentials/keyValue/dbUserPass # this shoud show you the secret
```
To get the created secret by Curl
```
kubectl -n $VAULT_K8S_NAMESPACE port-forward service/vault 8200:8200 > /dev/null 2>&1 & 
curl --cacert $WORKDIR/vault.ca --header "X-Vault-Token: $CLUSTER_ROOT_TOKEN" https://127.0.0.1:8200/v1/internal/data/database/config | jq .data.data
```

***
## Step 6. Configuring Kubernetes authentication
```
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault auth enable kubernetes
```
Get kubernetes api token and port:
```
token_reviewer=$(kubectl -n $VAULT_K8S_NAMESPACE -it exec vault-0 -- cat /var/run/secrets/kubernetes.io/serviceaccount/token)
KUBERNETES_PORT_443_TCP_ADDR="$(kubectl -n $VAULT_K8S_NAMESPACE -it exec vault-0 -- env | grep KUBERNETES_PORT_443_TCP_ADDR | cut -d = -f2)"
KUBERNETES_PORT_443_TCP_ADDR=$(echo ${KUBERNETES_PORT_443_TCP_ADDR:0:-1})    # to remove '$'r' from its end.
```
* `KUBERNETES_PORT_443_TCP_ADDR` defines and references the internal network address of the Kubernetes host
* Vault uses `token_reviewer` to authenticate itself when making calls with the Kubernetes API

Now, following command makes vault able to communicate with kubernetes api
```
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault write auth/kubernetes/config \
token_reviewer_jwt="$token_reviewer" \
kubernetes_host="https://${KUBERNETES_PORT_443_TCP_ADDR}:443" \
kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```


***
## Step 9. Creating a vault role and a policy for secret access
* To get access to the secrets stored in vault, you need to define a role and a policy.
* Below we create a secret-role which bounds `vault-credentials-service-account` to `vault-credentials-read-policy` in `test-ns` namespace.
* Now, using `vault-credentials-service-account` in deployment and pod files, we can access the secret.

```
kubectl -n $VAULT_K8S_NAMESPACE exec vault-0 -- vault write auth/kubernetes/role/secret-role \ 
bound_service_account_names=vault-credentials-service-account \
bound_service_account_namespaces=test-ns \
policies=vault-credentials-read-policy \
ttl=1h
```
Here is vault-credentials-read-policy
```
kubectl -n vault exec vault-0 -- sh -c "cat <<EOF > /home/vault/vault-policy.hcl
path \"credentials/data/keyValue/*\" {
  capabilities = ["read"]
}
EOF"

kubectl -n vault exec vault-0 -- vault policy write vault-credentials-read-policy /home/vault/vault-policy.hcl
```

***
## Step 8. an example yaml file to inject the secret
See `test-deployment.yaml` file and note to `annotations` section.
* in `agent-inject-secret-dbUserPasss.txt` agent-inject-secret is a prefix and dbUserPasss.txt will be the name of the injected secret. You can change it.
* injected secret will be stored in /vault/secrets/dbUserPasss.txt path inside the container.
* `credentials/keyValue/dbUserPass` is the path of secret in vault.
* `agent-inject-status: 'update'` is used to make update enable if we edit configs.

```
kube create ns test-ns
kubectl -n test-ns apply -f test-deployment.yaml
```

***
## Step 9. Testing
Display the secrets written to the file /vault/secrets/dbUserPass in `test-app` pod defined in the test-deployment.yaml.
```
kubectl -n test-ns exec --stdin=true --tty=true $(kubectl -n test-ns get pod | grep test-app | cut -d " " -f1) --container test-app -- cat /vault/secrets/dbuserpass.txt
```

output should be as following:
```
{
   "username" : username,
   "password" : password
}
```
