// Modèle des secrets du firmware — valeurs FACTICES, ce fichier est versionné.
// Copier en `secrets.h` (même dossier, ignoré par Git) et remplacer par les vraies valeurs.
#pragma once

// Point d'accès mobile Windows du groupe (bande 2,4 GHz obligatoire pour l'ESP32)
#define WIFI_SSID "RESILIENCE-G<n>"
#define WIFI_PASS "changeme-wifi-password"

// PC Hôte : adresse fixe du point d'accès, joignable via le WAF (port 80)
#define API_HOST "192.168.137.1"
#define API_PORT 80
#define LED_ENDPOINT "/api/auth/iot/led"

// Jeton partagé avec le service auth (variable IOT_DEVICE_TOKEN côté serveur, fournie par Vault/SOPS)
#define DEVICE_TOKEN "changeme-device-token"
