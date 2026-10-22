// LED de statut d'authentification du back-office — Freenove ESP32-WROVER (Arduino IDE)
//
// L'ESP32 interroge le PC Hôte (GET LED_ENDPOINT, via le WAF) et joue localement le motif demandé.
// Le serveur ne fait que publier { "pattern": ..., "seq": n } ; durées et clignotements sont gérés ici,
// pour qu'un retard réseau ne déforme pas l'affichage. Détails : docs/IOT.md.
//
// Test sans serveur (moniteur série 115200, « Pas de fin de ligne » ou « Nouvelle ligne ») :
//   0 = éteinte · 1 = vert clignotant · 2 = vert fixe 30 s · 3 = rouge ×10 · 4 = rouge fixe 30 s
//   a = retour au mode automatique (interrogation du serveur)

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "secrets.h"  // copier secrets.example.h → secrets.h (non versionné)

// --- Câblage (docs/IOT.md § 3) ---
const int PIN_GREEN = 13;
const int PIN_RED = 14;

// --- Temporisations (consigne additionnelle 1) ---
const unsigned long POLL_INTERVAL_MS = 300;
const unsigned long HTTP_TIMEOUT_MS = 1000;      // borne le temps bloqué si le PC Hôte ne répond pas
const unsigned long FAILSAFE_MS = 5000;          // sans réponse valide → LED éteinte
const unsigned long WIFI_RETRY_MS = 5000;
const unsigned long BLINK_HALF_PERIOD_MS = 250;  // 250 ms allumée / 250 ms éteinte
const unsigned long FIXED_DURATION_MS = 30000;
const int RED_BLINK_COUNT = 10;

enum Pattern { OFF, GREEN_BLINK, GREEN_FIXED_30S, RED_BLINK_X10, RED_FIXED_30S };

Pattern currentPattern = OFF;
unsigned long patternStartMs = 0;
long lastSeq = -1;               // -1 : aucun motif reçu depuis le démarrage
unsigned long lastValidReplyMs = 0;
unsigned long lastPollMs = 0;
unsigned long lastWifiAttemptMs = 0;
bool manualMode = false;         // true : piloté depuis le moniteur série, serveur ignoré

void setLeds(bool green, bool red) {
  digitalWrite(PIN_GREEN, green ? HIGH : LOW);
  digitalWrite(PIN_RED, red ? HIGH : LOW);
}

const char* patternName(Pattern p) {
  switch (p) {
    case GREEN_BLINK: return "GREEN_BLINK";
    case GREEN_FIXED_30S: return "GREEN_FIXED_30S";
    case RED_BLINK_X10: return "RED_BLINK_X10";
    case RED_FIXED_30S: return "RED_FIXED_30S";
    default: return "OFF";
  }
}

// Motif inconnu → OFF : on n'affiche jamais un état que l'on ne comprend pas.
Pattern parsePattern(const char* s) {
  if (s == nullptr) return OFF;
  if (strcmp(s, "GREEN_BLINK") == 0) return GREEN_BLINK;
  if (strcmp(s, "GREEN_FIXED_30S") == 0) return GREEN_FIXED_30S;
  if (strcmp(s, "RED_BLINK_X10") == 0) return RED_BLINK_X10;
  if (strcmp(s, "RED_FIXED_30S") == 0) return RED_FIXED_30S;
  return OFF;
}

void startPattern(Pattern p) {
  currentPattern = p;
  patternStartMs = millis();
  Serial.printf("[led] motif -> %s\n", patternName(p));
}

// Fait avancer le motif courant sans bloquer la boucle (aucun delay()).
void updateLeds() {
  unsigned long elapsed = millis() - patternStartMs;
  bool blinkOn = (elapsed / BLINK_HALF_PERIOD_MS) % 2 == 0;

  switch (currentPattern) {
    case OFF:
      setLeds(false, false);
      break;
    case GREEN_BLINK:  // jusqu'à ce que le serveur publie un autre motif
      setLeds(blinkOn, false);
      break;
    case GREEN_FIXED_30S:
      if (elapsed >= FIXED_DURATION_MS) startPattern(OFF);
      else setLeds(true, false);
      break;
    case RED_BLINK_X10:
      if (elapsed >= RED_BLINK_COUNT * 2 * BLINK_HALF_PERIOD_MS) startPattern(OFF);
      else setLeds(false, blinkOn);
      break;
    case RED_FIXED_30S:
      if (elapsed >= FIXED_DURATION_MS) startPattern(OFF);
      else setLeds(false, true);
      break;
  }
}

void ensureWifi() {
  if (WiFi.status() == WL_CONNECTED) return;
  if (millis() - lastWifiAttemptMs < WIFI_RETRY_MS && lastWifiAttemptMs != 0) return;
  lastWifiAttemptMs = millis();
  Serial.printf("[wifi] connexion a %s...\n", WIFI_SSID);
  WiFi.disconnect();
  WiFi.begin(WIFI_SSID, WIFI_PASS);
}

// Un nouveau motif n'est démarré que si `seq` change : un motif à durée limitée
// (vert 30 s, rouge ×10, rouge 30 s) n'est donc joué qu'une fois, même si la réponse est relue.
void pollServer() {
  if (WiFi.status() != WL_CONNECTED) return;

  HTTPClient http;
  http.setConnectTimeout(HTTP_TIMEOUT_MS);
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.begin(API_HOST, API_PORT, LED_ENDPOINT);
  http.addHeader("X-Device-Token", DEVICE_TOKEN);

  int status = http.GET();
  if (status != 200) {
    if (status == 401) Serial.println("[api] 401 : DEVICE_TOKEN refuse");
    else if (status < 0) Serial.printf("[api] erreur : %s\n", http.errorToString(status).c_str());
    else Serial.printf("[api] HTTP %d\n", status);
    http.end();
    return;
  }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, http.getStream());
  http.end();
  if (err || !doc["seq"].is<long>()) {
    Serial.println("[api] reponse JSON invalide");
    return;
  }

  lastValidReplyMs = millis();
  long seq = doc["seq"];
  if (seq != lastSeq) {  // « != » et non « > » : seq repart de 0 si le service auth redémarre
    lastSeq = seq;
    startPattern(parsePattern(doc["pattern"]));
  }
}

void handleSerial() {
  if (!Serial.available()) return;
  char c = Serial.read();
  if (c >= '0' && c <= '4') {
    manualMode = true;
    startPattern(static_cast<Pattern>(c - '0'));
  } else if (c == 'a') {
    manualMode = false;
    lastSeq = -1;  // rejouer le motif courant du serveur
    lastValidReplyMs = millis();
    Serial.println("[mode] automatique");
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_GREEN, OUTPUT);
  pinMode(PIN_RED, OUTPUT);
  setLeds(false, false);  // consigne : LED éteinte par défaut

  WiFi.mode(WIFI_STA);
  ensureWifi();
  Serial.println("[boot] led-status pret (0-4 = test manuel, a = automatique)");
}

void loop() {
  static bool wasConnected = false;
  bool connected = WiFi.status() == WL_CONNECTED;
  if (connected && !wasConnected) {
    Serial.printf("[wifi] connecte, IP %s\n", WiFi.localIP().toString().c_str());
  }
  wasConnected = connected;

  handleSerial();
  ensureWifi();

  if (!manualMode) {
    if (millis() - lastPollMs >= POLL_INTERVAL_MS) {
      lastPollMs = millis();
      pollServer();
    }
    // Fail-safe : SI injoignable → on n'affiche pas un état périmé (ex. un vert trompeur).
    if (currentPattern != OFF && millis() - lastValidReplyMs > FAILSAFE_MS) {
      Serial.println("[failsafe] plus de reponse du serveur -> LED eteinte");
      startPattern(OFF);
    }
  }

  updateLeds();
}
