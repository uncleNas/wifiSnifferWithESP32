/*
 * ESP32 Advanced Wi-Fi Sniffer - EMBEDDED WEB VERSION
 * No SPIFFS required - all files embedded in code
 */

#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include <map>
#include <vector>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>

// Configuration
#define CHANNEL_HOP_INTERVAL 500
#define MAX_DEVICES 100
#define LCD_ADDRESS 0x27  // Change to 0x3F if needed
#define LCD_COLS 20
#define LCD_ROWS 4
#define SDA_PIN 21
#define SCL_PIN 22

// LCD object
LiquidCrystal_I2C lcd(LCD_ADDRESS, LCD_COLS, LCD_ROWS);

// Web server
AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

// Device tracking structure
struct Device {
  uint8_t mac[6];
  String macStr;
  int8_t rssi;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint32_t packetCount;
  String vendor;
  uint8_t channel;
  bool isAP;
  String ssid;
};

// Security monitoring
struct SecurityEvent {
  uint32_t timestamp;
  String type;
  String description;
  uint8_t mac[6];
};

// Global variables
std::map<String, Device> devices;
std::vector<SecurityEvent> securityEvents;
uint32_t totalPackets = 0;
uint32_t channelPackets[14] = {0};
uint8_t currentChannel = 1;
uint32_t lastChannelSwitch = 0;
uint32_t deauthCount[14] = {0};

// Statistics
struct Stats {
  uint32_t mgmtFrames = 0;
  uint32_t ctrlFrames = 0;
  uint32_t dataFrames = 0;
  uint32_t beacons = 0;
  uint32_t probeReq = 0;
  uint32_t probeResp = 0;
  uint32_t deauth = 0;
};
// Vendor OUI database
struct VendorOUI {
  const char* oui;
  const char* vendor;
};

const VendorOUI vendorDB[] = {
  {"00:50:F2", "Microsoft"}, {"00:1B:63", "Apple"}, {"3C:28:6D", "Apple"},
  {"A4:83:E7", "Apple"}, {"BC:3B:AF", "Apple"}, {"70:3A:CB", "Apple"},
  {"00:1A:11", "Google"}, {"DA:A1:19", "Google"}, {"F4:F5:D8", "Google"},
  {"00:1F:3A", "Samsung"}, {"00:12:FB", "Samsung"}, {"E8:50:8B", "Samsung"},
  {"34:02:86", "Samsung"}, {"B4:07:F9", "Intel"}, {"00:1E:64", "Intel"},
  {"AC:22:0B", "Intel"}, {"00:24:D7", "Intel"}, {"DC:85:DE", "Xiaomi"},
  {"50:8F:4C", "Xiaomi"}, {"34:CE:00", "Xiaomi"}, {"00:C0:CA", "Cisco"},
  {"00:0C:85", "Cisco"}, {"00:26:99", "Cisco"}, {"B0:B9:8A", "Huawei"},
  {"00:E0:FC", "Huawei"}, {"48:DA:35", "Huawei"}, {NULL, NULL}
};

// Embedded HTML
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ESP32 Wi-Fi Sniffer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px;color:#333}
.container{max-width:1400px;margin:0 auto;background:#fff;border-radius:15px;box-shadow:0 20px 60px rgba(0,0,0,0.3);overflow:hidden}
header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;padding:30px;text-align:center}
header h1{font-size:2em;margin-bottom:10px}
.status{display:flex;justify-content:center;gap:15px;margin-top:15px}
.status-badge,.channel-badge{background:rgba(255,255,255,0.2);padding:8px 16px;border-radius:20px;font-size:0.9em}
.status-badge.connected{background:rgba(76,175,80,0.3)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;padding:30px;background:#f5f5f5}
.stat-card{background:#fff;padding:25px;border-radius:10px;text-align:center;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
.stat-value{font-size:2.5em;font-weight:bold;color:#667eea;margin-bottom:10px}
.stat-label{color:#666;font-size:0.9em;text-transform:uppercase}
.content{padding:30px}
table{width:100%;border-collapse:collapse;background:#fff;margin-top:20px}
thead{background:#667eea;color:#fff}
th,td{padding:12px;text-align:left;border-bottom:1px solid #eee}
th{font-weight:600}
tbody tr:hover{background:#f8f9fa}
.device-type{display:inline-block;padding:4px 12px;border-radius:12px;font-size:0.8em;font-weight:600}
.device-type.ap{background:#e3f2fd;color:#1976d2}
.device-type.client{background:#f3e5f5;color:#7b1fa2}
button{padding:10px 20px;border:none;border-radius:8px;background:#667eea;color:#fff;cursor:pointer;margin:5px}
button:hover{background:#5568d3}
</style>
</head>
<body>
<div class="container">
<header>
<h1>🛡️ ESP32 Wi-Fi Sniffer</h1>
<div class="status">
<span id="status" class="status-badge">Connecting...</span>
<span class="channel-badge">Channel: <span id="currentChannel">-</span></span>
</div>
</header>
<div class="stats-grid">
<div class="stat-card"><div class="stat-value" id="totalPackets">0</div><div class="stat-label">Total Packets</div></div>
<div class="stat-card"><div class="stat-value" id="uniqueDevices">0</div><div class="stat-label">Unique Devices</div></div>
<div class="stat-card"><div class="stat-value" id="mgmtFrames">0</div><div class="stat-label">Management Frames</div></div>
<div class="stat-card"><div class="stat-value" id="deauthFrames">0</div><div class="stat-label">Deauth Frames</div></div>
</div>
<div class="content">
<h2>Detected Devices</h2>
<button onclick="clearData()">Clear Data</button>
<button onclick="location.reload()">Refresh</button>
<table>
<thead><tr><th>MAC Address</th><th>Vendor</th><th>RSSI</th><th>Packets</th><th>Channel</th><th>Type</th><th>Last Seen</th></tr></thead>
<tbody id="deviceList"><tr><td colspan="7" style="text-align:center;padding:40px">Waiting for data...</td></tr></tbody>
</table>
</div>
</div>
<script>
let ws;
let devices=[];
let stats={};
function initWebSocket(){
ws=new WebSocket(`ws://${window.location.hostname}/ws`);
ws.onopen=function(){
document.getElementById('status').textContent='Connected';
document.getElementById('status').classList.add('connected');
ws.send('getDevices');
ws.send('getStats');
};
ws.onclose=function(){
document.getElementById('status').textContent='Disconnected';
document.getElementById('status').classList.remove('connected');
setTimeout(initWebSocket,3000);
};
ws.onmessage=function(e){
try{
const data=JSON.parse(e.data);
if(data.devices){devices=data.devices;updateDeviceTable();}
if(data.totalPackets!==undefined){stats=data;updateStats();}
}catch(err){console.error(err);}
};
}
function updateStats(){
document.getElementById('totalPackets').textContent=stats.totalPackets.toLocaleString();
document.getElementById('uniqueDevices').textContent=stats.uniqueDevices;
document.getElementById('mgmtFrames').textContent=stats.mgmtFrames.toLocaleString();
document.getElementById('deauthFrames').textContent=stats.deauth;
document.getElementById('currentChannel').textContent=stats.currentChannel;
}
function updateDeviceTable(){
const tbody=document.getElementById('deviceList');
if(devices.length===0){
tbody.innerHTML='<tr><td colspan="7" style="text-align:center;padding:40px">No devices detected yet</td></tr>';
return;
}
let html='';
devices.forEach(d=>{
const type=d.isAP?'<span class="device-type ap">AP</span>':'<span class="device-type client">Client</span>';
const ssid=d.ssid?'<br><small>'+d.ssid+'</small>':'';
html+=`<tr><td><code>${d.mac}</code></td><td>${d.vendor}</td><td>${d.rssi} dBm</td><td>${d.packets.toLocaleString()}</td><td>${d.channel}</td><td>${type}${ssid}</td><td>${d.lastSeen}s ago</td></tr>`;
});
tbody.innerHTML=html;
}
function clearData(){
if(confirm('Clear all data?')){
if(ws&&ws.readyState===WebSocket.OPEN){
ws.send('clearData');
devices=[];
updateDeviceTable();
}
}
}
window.addEventListener('load',function(){
initWebSocket();
setInterval(function(){
if(ws&&ws.readyState===WebSocket.OPEN){
ws.send('getDevices');
ws.send('getStats');
}
},5000);
});
</script>
</body>
</html>
)rawliteral";

// Packet callback function
void IRAM_ATTR packetHandler(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
  const uint8_t* payload = pkt->payload;
  
  totalPackets++;
  channelPackets[currentChannel]++;
  
  uint8_t frameType = (payload[0] & 0x0C) >> 2;
  uint8_t frameSubType = (payload[0] & 0xF0) >> 4;
  
  if (frameType == 0) {
    stats.mgmtFrames++;
    if (frameSubType == 8) stats.beacons++;
    else if (frameSubType == 4) stats.probeReq++;
    else if (frameSubType == 5) stats.probeResp++;
    else if (frameSubType == 12) {
      stats.deauth++;
      deauthCount[currentChannel]++;
      if (deauthCount[currentChannel] > 10) {
        SecurityEvent evt;
        evt.timestamp = millis();
        evt.type = "DEAUTH_ATTACK";
        evt.description = "Multiple deauth frames on Ch" + String(currentChannel);
        memcpy(evt.mac, &payload[4], 6);
        if (securityEvents.size() < 50) securityEvents.push_back(evt);
      }
    }
  } else if (frameType == 1) {
    stats.ctrlFrames++;
  } else if (frameType == 2) {
    stats.dataFrames++;
  }
  
  uint8_t srcMAC[6];
  memcpy(srcMAC, &payload[10], 6);
  
  char macStr[18];
  sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X",
          srcMAC[0], srcMAC[1], srcMAC[2], srcMAC[3], srcMAC[4], srcMAC[5]);
  
  String macString = String(macStr);
  
  if (devices.find(macString) == devices.end()) {
    Device dev;
    memcpy(dev.mac, srcMAC, 6);
    dev.macStr = macString;
    dev.rssi = ctrl.rssi;
    dev.firstSeen = millis();
    dev.lastSeen = millis();
    dev.packetCount = 1;
    dev.channel = currentChannel;
    dev.isAP = (frameSubType == 8);
    
    if (frameSubType == 8 && pkt->rx_ctrl.sig_len > 40) {
      uint8_t ssidLen = payload[37];
      if (ssidLen > 0 && ssidLen < 33) {
        char ssid[33] = {0};
        memcpy(ssid, &payload[38], ssidLen);
        dev.ssid = String(ssid);
      }
    }
    
    char ouiStr[9];
    sprintf(ouiStr, "%02X:%02X:%02X", srcMAC[0], srcMAC[1], srcMAC[2]);
    dev.vendor = lookupVendor(ouiStr);
    
    devices[macString] = dev;
  } else {
    devices[macString].lastSeen = millis();
    devices[macString].packetCount++;
    devices[macString].rssi = ctrl.rssi;
  }
}

String lookupVendor(const char* oui) {
  for (int i = 0; vendorDB[i].oui != NULL; i++) {
    if (strcmp(oui, vendorDB[i].oui) == 0) {
      return String(vendorDB[i].vendor);
    }
  }
  return "Unknown";
}

void channelHop() {
  if (millis() - lastChannelSwitch > CHANNEL_HOP_INTERVAL) {
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastChannelSwitch = millis();
    deauthCount[currentChannel] = 0;
  }
}

void onWsEvent(AsyncWebSocket *server, AsyncWebSocketClient *client,
               AwsEventType type, void *arg, uint8_t *data, size_t len) {
  if (type == WS_EVT_CONNECT) {
    Serial.println("WebSocket connected");
    sendDeviceList(client);
  } else if (type == WS_EVT_DATA) {
    AwsFrameInfo *info = (AwsFrameInfo*)arg;
    if (info->final && info->index == 0 && info->len == len) {
      data[len] = 0;
      String msg = String((char*)data);
      
      if (msg == "getDevices") {
        sendDeviceList(client);
      } else if (msg == "getStats") {
        sendStats(client);
      } else if (msg == "clearData") {
        devices.clear();
        securityEvents.clear();
        totalPackets = 0;
        memset(channelPackets, 0, sizeof(channelPackets));
        client->text("{\"status\":\"cleared\"}");
      }
    }
  }
}

void sendDeviceList(AsyncWebSocketClient *client) {
  DynamicJsonDocument doc(8192);
  JsonArray devArray = doc.createNestedArray("devices");
  
  uint32_t now = millis();
  int count = 0;
  
  for (auto& pair : devices) {
    if (count++ >= MAX_DEVICES) break;
    Device& dev = pair.second;
    if (now - dev.lastSeen > 300000) continue;
    
    JsonObject devObj = devArray.createNestedObject();
    devObj["mac"] = dev.macStr;
    devObj["rssi"] = dev.rssi;
    devObj["vendor"] = dev.vendor;
    devObj["packets"] = dev.packetCount;
    devObj["channel"] = dev.channel;
    devObj["isAP"] = dev.isAP;
    devObj["ssid"] = dev.ssid;
    devObj["lastSeen"] = (now - dev.lastSeen) / 1000;
  }
  
  String output;
  serializeJson(doc, output);
  if (client) {
    client->text(output);
  } else {
    ws.textAll(output);
  }
}

void sendStats(AsyncWebSocketClient *client) {
  DynamicJsonDocument doc(2048);
  
  doc["totalPackets"] = totalPackets;
  doc["uniqueDevices"] = devices.size();
  doc["currentChannel"] = currentChannel;
  doc["mgmtFrames"] = stats.mgmtFrames;
  doc["ctrlFrames"] = stats.ctrlFrames;
  doc["dataFrames"] = stats.dataFrames;
  doc["beacons"] = stats.beacons;
  doc["probeReq"] = stats.probeReq;
  doc["deauth"] = stats.deauth;
  doc["uptime"] = millis() / 1000;
  
  JsonArray chArray = doc.createNestedArray("channelActivity");
  for (int i = 1; i <= 13; i++) {
    chArray.add(channelPackets[i]);
  }
  
  String output;
  serializeJson(doc, output);
  if (client) {
    client->text(output);
  } else {
    ws.textAll(output);
  }
}

void updateLCDDisplay() {
  static uint32_t lastLCDUpdate = 0;
  if (millis() - lastLCDUpdate < 1000) return;
  lastLCDUpdate = millis();
  
  lcd.setCursor(0, 0);
  lcd.printf("Pkts:%06d Dev:%02d", totalPackets, devices.size());
  
  lcd.setCursor(0, 1);
  int avgRssi = 0;
  if (devices.size() > 0) {
    int rssiSum = 0;
    for (auto& pair : devices) {
      rssiSum += pair.second.rssi;
    }
    avgRssi = rssiSum / devices.size();
  }
  lcd.printf("Ch:%2d RSSI:%4ddBm", currentChannel, avgRssi);
  
  lcd.setCursor(0, 2);
  lcd.printf("Bcn:%04d Prb:%04d", stats.beacons, stats.probeReq);
  
  lcd.setCursor(0, 3);
  uint32_t uptime = millis() / 1000;
  uint32_t hours = uptime / 3600;
  uint32_t minutes = (uptime % 3600) / 60;
  lcd.printf("Dea:%03d Up:%02d:%02d", stats.deauth, hours, minutes);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n\nESP32 Advanced Wi-Fi Sniffer");
  Serial.println("=============================");
  
  // Initialize I2C and LCD
  Wire.begin(SDA_PIN, SCL_PIN);
  lcd.init();
  lcd.backlight();
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("ESP32 Sniffer");
  lcd.setCursor(0, 1);
  lcd.print("Initializing...");
  delay(1000);
  lcd.clear();
  
  // Start WiFi in AP mode
  WiFi.mode(WIFI_AP);
  WiFi.softAP("ESP32-Sniffer", "sniffer123");
  Serial.print("AP IP: ");
  Serial.println(WiFi.softAPIP());
  
  // Configure promiscuous mode
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&packetHandler);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  
  // Setup WebSocket
  ws.onEvent(onWsEvent);
  server.addHandler(&ws);
  
  // Serve embedded HTML
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/html", index_html);
  });
  
  // API endpoint
  server.on("/api/export", HTTP_GET, [](AsyncWebServerRequest *request) {
    DynamicJsonDocument doc(16384);
    JsonArray devArray = doc.createNestedArray("devices");
    
    for (auto& pair : devices) {
      JsonObject devObj = devArray.createNestedObject();
      Device& dev = pair.second;
      devObj["mac"] = dev.macStr;
      devObj["vendor"] = dev.vendor;
      devObj["packets"] = dev.packetCount;
      devObj["firstSeen"] = dev.firstSeen;
      devObj["lastSeen"] = dev.lastSeen;
    }
    
    String output;
    serializeJson(doc, output);
    request->send(200, "application/json", output);
  });
  
  server.begin();
  Serial.println("Web server started");
  Serial.println("Connect: ESP32-Sniffer (sniffer123)");
  Serial.println("Browser: http://192.168.4.1");
}

void loop() {
  channelHop();
  ws.cleanupClients();
  updateLCDDisplay();
  
  static uint32_t lastUpdate = 0;
  if (millis() - lastUpdate > 2000) {
    sendDeviceList(nullptr);
    sendStats(nullptr); 
    lastUpdate = millis();
    
    Serial.printf("Pkts: %d | Dev: %d | Ch: %d | Deauth: %d\n",
                  totalPackets, devices.size(), currentChannel, stats.deauth);
  }
  
  delay(10);
}