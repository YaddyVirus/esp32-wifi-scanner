// ESP32 Wi-Fi scanner: scans the 2.4 GHz band on a loop, logs every result,
// sniffs client devices in promiscuous mode, and serves it all on a small webpage.
#include <WiFi.h>
#include <WebServer.h>
#include <esp_wifi.h>

// Your Wi-Fi network. The ESP32 only supports 2.4 GHz, so use a 2.4 GHz SSID.
const char *WIFI_SSID = "your-network-name";
const char *WIFI_PASS = "your-wifi-password";

const uint32_t SCAN_EVERY_MS = 5000;
WebServer server(80);

struct Ap { String ssid; uint8_t bssid[6]; int32_t rssi; uint8_t ch; wifi_auth_mode_t auth; };
Ap aps[64]; int apCount = 0;
uint32_t scanNo = 0, lastScanStart = 0, lastScanMs = 0;

// Last known channel per BSSID, to log neighbors hopping channels.
struct Seen { uint8_t bssid[6]; uint8_t ch; };
Seen seen[96]; int seenCount = 0;

String logLines[40]; int logHead = 0, logCount = 0;

struct Device { uint8_t mac[6]; int8_t rssi; uint32_t frames, lastSeen; bool probe; };
Device clients[64]; volatile int clientCount = 0;
portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;

String uptime(uint32_t ms) {
  char b[16]; uint32_t s = ms / 1000;
  snprintf(b, sizeof b, "%02lu:%02lu:%02lu", s / 3600, (s / 60) % 60, s % 60); return b;
}

void addLog(const String &line) {
  logLines[logHead] = uptime(millis()) + "  " + line;
  logHead = (logHead + 1) % 40; if (logCount < 40) logCount++;
  Serial.println(line);
}

String macStr(const uint8_t *m) {
  char b[18]; snprintf(b, sizeof b, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]); return b;
}
bool isRandomized(const uint8_t *m) { return m[0] & 0x02; }  // locally administered bit

const char *authName(wifi_auth_mode_t a) {
  switch (a) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Ent";
    default: return "Other";
  }
}

void IRAM_ATTR sniff(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *f = p->payload;
  uint8_t ftype = (f[0] >> 2) & 3, subtype = (f[0] >> 4) & 0xF, toDS = f[1] & 0x01, fromDS = f[1] & 0x02;
  bool probe = (ftype == 0 && subtype == 4);
  bool fromClient = (ftype == 2 && toDS && !fromDS);
  if (!probe && !fromClient) return;
  const uint8_t *mac = f + 10;  // addr2 = transmitter
  portENTER_CRITICAL_ISR(&mux);
  int i = 0;
  for (; i < clientCount; i++) if (!memcmp(clients[i].mac, mac, 6)) break;
  if (i == clientCount && clientCount < 64) { memcpy(clients[i].mac, mac, 6); clients[i].frames = 0; clients[i].probe = false; clientCount++; }
  if (i < 64) {
    clients[i].rssi = p->rx_ctrl.rssi; clients[i].frames++; clients[i].lastSeen = millis();
    clients[i].probe |= probe;
  }
  portEXIT_CRITICAL_ISR(&mux);
}

void collectScan(int n) {
  lastScanMs = millis() - lastScanStart; scanNo++;
  apCount = 0;
  int perCh[14] = {0};
  for (int i = 0; i < n && apCount < 64; i++) {
    Ap &a = aps[apCount++];
    a.ssid = WiFi.SSID(i); memcpy(a.bssid, WiFi.BSSID(i), 6);
    a.rssi = WiFi.RSSI(i); a.ch = WiFi.channel(i); a.auth = WiFi.encryptionType(i);
    if (a.ch < 14) perCh[a.ch]++;
    int s = 0;
    for (; s < seenCount; s++) if (!memcmp(seen[s].bssid, a.bssid, 6)) break;
    if (s == seenCount && seenCount < 96) { memcpy(seen[s].bssid, a.bssid, 6); seen[s].ch = a.ch; seenCount++; }
    if (s < seenCount && seen[s].ch != a.ch) {
      addLog("\"" + (a.ssid.length() ? a.ssid : String("(hidden)")) + "\" moved ch " + seen[s].ch + " -> " + a.ch);
      seen[s].ch = a.ch;
    }
  }
  String busy = "";
  for (int c = 1; c <= 13; c++) if (perCh[c]) busy += " ch" + String(c) + ":" + perCh[c];
  addLog("scan #" + String(scanNo) + ": " + apCount + " APs in " + lastScanMs + " ms |" + busy);
  WiFi.scanDelete();
}

String json() {
  String j = "{\"scan\":" + String(scanNo) + ",\"scanMs\":" + lastScanMs + ",\"every\":" + SCAN_EVERY_MS +
             ",\"uptime\":\"" + uptime(millis()) + "\",\"heap\":" + ESP.getFreeHeap() +
             ",\"home\":\"" + WiFi.SSID() + "\",\"homeCh\":" + WiFi.channel() + ",\"aps\":[";
  for (int i = 0; i < apCount; i++) {
    const Ap &a = aps[i]; String s = a.ssid; s.replace("\\", "\\\\"); s.replace("\"", "\\\"");
    j += String(i ? "," : "") + "{\"ssid\":\"" + s + "\",\"bssid\":\"" + macStr(a.bssid) + "\",\"rssi\":" + a.rssi +
         ",\"ch\":" + a.ch + ",\"sec\":\"" + authName(a.auth) + "\"}";
  }
  j += "],\"clients\":[";
  portENTER_CRITICAL(&mux);
  int n = clientCount; Device copy[64]; memcpy(copy, clients, sizeof(Device) * n);
  portEXIT_CRITICAL(&mux);
  for (int i = 0; i < n; i++) {
    const Device &c = copy[i]; bool rnd = isRandomized(c.mac);
    j += String(i ? "," : "") + "{\"id\":\"" + macStr(c.mac) + "\",\"rnd\":" + (rnd ? "true" : "false") + ",\"rssi\":" + c.rssi +
         ",\"frames\":" + c.frames + ",\"ago\":" + (millis() - c.lastSeen) / 1000 + ",\"probe\":" + (c.probe ? "true" : "false") + "}";
  }
  j += "],\"log\":[";
  for (int i = 0; i < logCount; i++) {
    String l = logLines[(logHead - 1 - i + 40) % 40]; l.replace("\"", "\\\"");
    j += String(i ? "," : "") + "\"" + l + "\"";
  }
  return j + "]}";
}

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ESP32 Wi-Fi Scanner</title>
<style>
body{margin:0;font:15px system-ui,sans-serif;background:#0f1419;color:#e6e6e6}
header{padding:18px 28px;background:#151c24;border-bottom:1px solid #26313d;display:flex;gap:28px;align-items:baseline;flex-wrap:wrap}
h1{font-size:22px;margin:0 12px 0 0}.stat b{color:#7fd1ff;font-size:18px}.stat{color:#9aa7b4}
main{display:grid;grid-template-columns:1.35fr 1fr;gap:22px;padding:22px 28px}
section{background:#151c24;border:1px solid #26313d;border-radius:10px;padding:16px 18px}
h2{font-size:15px;margin:0 0 12px;color:#9aa7b4;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse}td,th{padding:6px 8px;text-align:left;border-bottom:1px solid #222c37}
th{color:#7d8a97;font-weight:600;font-size:13px}.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.bar{height:8px;border-radius:4px;background:linear-gradient(90deg,#ff6b6b,#ffd166,#06d6a0)}
.chs{display:flex;gap:6px;align-items:flex-end;height:260px;padding-top:6px}
.ch{flex:1;text-align:center;font-size:12px;color:#9aa7b4}.ch div{background:#3a86ff;border-radius:4px 4px 0 0;margin-bottom:4px}
.home{color:#06d6a0;font-weight:600}.log{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;line-height:1.6;max-height:300px;overflow:auto;color:#c9d3dd}
.tag{font-size:11px;padding:1px 6px;border-radius:8px;background:#26313d;color:#9aa7b4}
</style></head><body>
<header><h1>ESP32 Wi-Fi Scanner</h1>
<span class="stat">Scan <b id="scan">-</b></span><span class="stat">Every <b id="every">-</b></span>
<span class="stat">Last sweep <b id="ms">-</b></span><span class="stat">Uptime <b id="up">-</b></span>
<span class="stat">Free RAM <b id="heap">-</b></span></header>
<main>
<section style="grid-row:span 2"><h2>Access points (2.4 GHz)</h2>
<table><thead><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Security</th><th>Signal</th><th></th></tr></thead><tbody id="aps"></tbody></table></section>
<section><h2>Channel congestion</h2><div class="chs" id="chs"></div></section>
<section><h2>Client devices (promiscuous mode)</h2>
<table><thead><tr><th>Device</th><th>Seen as</th><th>Signal</th><th>Frames</th><th>Last</th></tr></thead><tbody id="cl"></tbody></table></section>
<section style="grid-column:span 2"><h2>Scan log</h2><div class="log" id="log"></div></section>
</main>
<script>
const esc=s=>s.replace(/[&<>\x22\x27]/g,c=>'&#'+c.charCodeAt(0)+';');
async function tick(){
 const d=await (await fetch('/api')).json();
 scan.textContent='#'+d.scan; every.textContent=d.every/1000+' s'; ms.textContent=d.scanMs+' ms'; up.textContent=d.uptime; heap.textContent=Math.round(d.heap/1024)+' KB';
 const aps=d.aps.sort((a,b)=>b.rssi-a.rssi);
 document.getElementById('aps').innerHTML=aps.map(a=>`<tr><td class="${a.ssid==d.home?'home':''}">${a.ssid?esc(a.ssid):'<i>(hidden)</i>'}</td><td class="mono">${a.bssid}</td><td>${a.ch}</td><td>${a.sec}</td><td class="mono">${a.rssi} dBm</td><td style="width:110px"><div class="bar" style="width:${Math.max(6,Math.min(100,(a.rssi+95)*1.8))}%"></div></td></tr>`).join('');
 const c=Array(14).fill(0); aps.forEach(a=>c[a.ch]++); const m=Math.max(1,...c);
 chs.innerHTML=c.slice(1).map((n,i)=>`<div class="ch"><div style="height:${n/m*220}px;${i+1==d.homeCh?'background:#06d6a0':''}"></div>${i+1}<br><b>${n}</b></div>`).join('');
 const cl=d.clients.sort((a,b)=>a.ago-b.ago).slice(0,14);
 document.getElementById('cl').innerHTML=cl.map(x=>`<tr><td class="mono">${x.id}${x.rnd?' <span class="tag">randomized</span>':''}</td><td>${x.probe?'<span class="tag">probe request</span>':'<span class="tag">data</span>'}</td><td class="mono">${x.rssi} dBm</td><td>${x.frames}</td><td>${x.ago}s ago</td></tr>`).join('')+`<tr><td colspan=5 style="color:#7d8a97">${d.clients.length} devices heard, ${d.clients.filter(x=>x.rnd).length} with randomized MACs</td></tr>`;
 log.innerHTML=d.log.map(esc).join('<br>');
}
tick(); setInterval(tick,3000);
</script></body></html>)HTML";

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting");
  for (int i = 0; i < 60 && WiFi.status() != WL_CONNECTED; i++) { delay(500); Serial.print("."); }
  Serial.println(WiFi.status() == WL_CONNECTED ? "\nConnected, open http://" + WiFi.localIP().toString() : "\nWi-Fi connect failed");

  wifi_promiscuous_filter_t filt = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA};
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniff);
  esp_wifi_set_promiscuous(true);

  server.on("/", [] { server.send_P(200, "text/html", PAGE); });
  server.on("/api", [] { server.send(200, "application/json", json()); });
  server.begin();
}

void loop() {
  server.handleClient();
  int n = WiFi.scanComplete();
  if (n >= 0) collectScan(n);
  if (n != WIFI_SCAN_RUNNING && millis() - lastScanStart >= SCAN_EVERY_MS) {
    lastScanStart = millis();
    WiFi.scanNetworks(true, true);  // async, include hidden networks
  }
}
