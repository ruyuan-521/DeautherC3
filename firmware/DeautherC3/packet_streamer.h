// packet_streamer.h - TCP streamer for captured 802.11 packets
// Captured frames are stored in a ring buffer, then streamed to a remote server
// via TCP connection. The server decodes frames with Scapy and displays them.
#ifndef PACKET_STREAMER_H
#define PACKET_STREAMER_H

#include <WiFiClient.h>
#include <stdint.h>

#define PACKET_RING_SIZE     30     // Max packets in ring buffer (reduced: 30×512=15KB vs 100×512=51KB)
#define MAX_FRAME_SIZE       512    // Max frame size we store (truncated if larger)
#define SERVER_PORT          9999   // Default TCP port for streaming

// Packet entry in the ring buffer
struct PacketEntry {
  uint8_t  frame_data[MAX_FRAME_SIZE]; // Raw 802.11 frame bytes
  uint16_t frame_len;                  // Actual frame length
  uint8_t  channel;                    // Channel where captured
  int8_t   rssi;                       // Signal strength
  uint32_t timestamp_ms;               // Capture time (millis())
  bool     valid;                      // Is this slot occupied?
};

class PacketStreamer {
public:
  PacketStreamer();

  // Configuration
  void setServer(const char* ip, uint16_t port = SERVER_PORT);
  void setWiFi(const char* ssid, const char* password);

  // BSSID filter - only stream frames from a specific WiFi network
  void setFilterBSSID(const uint8_t* bssid);  // 6-byte MAC of target AP
  void clearFilter();                          // Remove BSSID filter (stream all)
  bool isFilterActive();

  // Ring buffer operations
  bool pushPacket(const uint8_t* data, uint16_t len, uint8_t channel, int8_t rssi);
  int  getBufferCount();              // How many unsent packets in buffer

  // Connection management
  bool connectToServer();
  void disconnect();
  bool isConnected();
  bool ensureConnected();             // Auto-reconnect if needed

  // Streaming - call in main loop
  void loop();                        // Send buffered packets, handle reconnect

  // Stats
  uint32_t getPacketsSent();
  uint32_t getPacketsDropped();

private:
  // Ring buffer
  PacketEntry buffer_[PACKET_RING_SIZE];
  int         head_;                  // Write position
  int         tail_;                  // Read position
  int         count_;                 // Packets in buffer
  uint32_t    total_pushed_;          // Total packets ever pushed
  uint32_t    dropped_;               // Dropped due to full buffer

  // Server connection
  char        server_ip_[16];         // Server IP string
  uint16_t    server_port_;
  WiFiClient  client_;
  bool        connected_;

  // WiFi for STA mode (connect to router for internet)
  const char* sta_ssid_;
  const char* sta_password_;
  bool        wifi_connected_;

  // Stats
  uint32_t    sent_count_;

  // BSSID filter (only stream frames matching this AP MAC)
  uint8_t     filter_bssid_[6];
  bool        filter_enabled_;

  // Internal methods
  void sendPacket(const PacketEntry& pkt);
};

#endif  // PACKET_STREAMER_H
