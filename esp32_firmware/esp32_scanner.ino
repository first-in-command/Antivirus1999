// ESP32 : répond aux commandes série "WIFI" et "BLE" par une ligne JSON.
#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

const char* authName(wifi_auth_mode_t a){ return a==WIFI_AUTH_OPEN ? "OUVERT" : a==WIFI_AUTH_WEP ? "WEP" : "WPA/WPA2/WPA3"; }

void setup(){ Serial.begin(115200); WiFi.mode(WIFI_STA); WiFi.disconnect(); BLEDevice::init(""); }

void loop(){
  if(!Serial.available()) return;
  String cmd = Serial.readStringUntil('\n'); cmd.trim(); cmd.toUpperCase();
  if(cmd=="WIFI"){
    int n = WiFi.scanNetworks();
    Serial.print("{\"type\":\"wifi\",\"results\":[");
    for(int i=0;i<n;i++){
      if(i) Serial.print(",");
      Serial.printf("{\"ssid\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"channel\":%d,\"auth\":\"%s\"}",
        WiFi.SSID(i).c_str(), WiFi.BSSIDstr(i).c_str(), WiFi.RSSI(i), WiFi.channel(i), authName(WiFi.encryptionType(i)));
    }
    Serial.println("]}");
  } else if(cmd=="BLE"){
    BLEScan* s = BLEDevice::getScan(); s->setActiveScan(true);
    BLEScanResults* r = s->start(5, false);
    Serial.print("{\"type\":\"ble\",\"results\":[");
    for(int i=0;i<r->getCount();i++){
      BLEAdvertisedDevice d = r->getDevice(i); if(i) Serial.print(",");
      Serial.printf("{\"name\":\"%s\",\"address\":\"%s\",\"rssi\":%d}", d.getName().c_str(), d.getAddress().toString().c_str(), d.getRSSI());
    }
    Serial.println("]}"); s->clearResults();
  }
}
