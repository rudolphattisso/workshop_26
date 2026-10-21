# HashiCorp Vault — serveur mono-nœud, stockage fichier persistant (volume vault-data).
# TLS désactivé : Vault n'est joignable que sur des réseaux Docker internes + loopback
# (127.0.0.1:8200 pour l'UI). En production : TLS obligatoire + stockage Raft/HA + auto-unseal KMS.
ui            = true
disable_mlock = true          # conteneur sans IPC_LOCK
api_addr      = "http://vault:8200"

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}
