#include <bluefruit.h>

// -----------------------------------------------------------------------------
// OpenTag GATT control
// -----------------------------------------------------------------------------
// 0 = NORMAL, 1 = ELVESZETT (lost)
//
// The browser uses GATT only for a short control transaction; RSSI measurement
// itself is advertising-based. Advertising is restarted from loop(), not from
// the BLE event callbacks.
// -----------------------------------------------------------------------------

BLEService controlService("19b10000-e8f2-537e-4f6c-d104768a1214");
BLECharacteristic modeCharacteristic("19b10001-e8f2-537e-4f6c-d104768a1214");

volatile bool restartAdvertisingPending = false;
volatile bool lostMode = false;

// Normal mode
const uint16_t NORMAL_INTERVAL_MS = 1000;
const int8_t   NORMAL_TX_POWER    = 4;

// Lost mode
const uint16_t LOST_INTERVAL_MS = 100;
const int8_t   LOST_TX_POWER    = 8;

// LED heartbeat (short pulse instead of 50 % duty: saves power)
const uint32_t NORMAL_LED_PERIOD_MS = 2000;
const uint32_t LOST_LED_PERIOD_MS   = 300;
const uint32_t LED_PULSE_MS         = 30;

// -----------------------------------------------------------------------------
// Advertising
// -----------------------------------------------------------------------------

// addTxPower() copies the *current* TX power into the packet when it is called.
// The packet therefore has to be rebuilt after every setTxPower(), otherwise the
// webapp keeps seeing the TX power from setup() (0 dBm) in both modes.
void buildAdvertisingData()
{
  Bluefruit.Advertising.clearData();
  Bluefruit.Advertising.addFlags(BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE);
  Bluefruit.Advertising.addTxPower();
  Bluefruit.Advertising.addName();
}

void startAdvertisingMode(bool lost)
{
  if (Bluefruit.Advertising.isRunning()) {
    Bluefruit.Advertising.stop();
  }

  lostMode = lost;

  const int8_t   txPower  = lost ? LOST_TX_POWER    : NORMAL_TX_POWER;
  const uint16_t interval = lost ? LOST_INTERVAL_MS : NORMAL_INTERVAL_MS;

  Bluefruit.setTxPower(txPower);
  buildAdvertisingData();

  // Same fast/slow interval, so the 30 s fast->slow transition changes nothing.
  Bluefruit.Advertising.setIntervalMS(interval, interval);

  // 0 = advertise continuously.
  Bluefruit.Advertising.start(0);

  Serial.print("Advertising mode: ");
  Serial.println(lost ? "LOST" : "NORMAL");
}

// -----------------------------------------------------------------------------
// BLE callbacks
// -----------------------------------------------------------------------------

void connect_callback(uint16_t conn_handle)
{
  Serial.print("GATT connected, handle: ");
  Serial.println(conn_handle);
}

void disconnect_callback(uint16_t conn_handle, uint8_t reason)
{
  (void) conn_handle;

  Serial.print("GATT disconnected, reason: 0x");
  Serial.println(reason, HEX);

  // Defer restarting advertising to loop().
  restartAdvertisingPending = true;
}

void mode_write_callback(uint16_t conn_hdl, BLECharacteristic* chr,
                         uint8_t* data, uint16_t len)
{
  (void) conn_hdl;
  (void) chr;

  if (len < 1 || data[0] > 1) {
    Serial.println("GATT write ignored: invalid payload");
    return;
  }

  lostMode = (data[0] == 1);

  // Let the webapp read the accepted value back.
  modeCharacteristic.write8(data[0]);

  Serial.print("GATT mode command accepted: ");
  Serial.println(lostMode ? "LOST (1)" : "NORMAL (0)");

  // Parameters are applied from loop() once the central has disconnected.
  restartAdvertisingPending = true;
}

// -----------------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------------

void setup()
{
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH);   // XIAO LED is active-low: HIGH = off

  Serial.begin(115200);
  delay(300);

  // Stop the library from driving the connection LED; loop() owns the LED.
  Bluefruit.autoConnLed(false);

  // One peripheral connection is enough for this tracker.
  Bluefruit.begin(1, 0);
  Bluefruit.setName("OpenTag-Test");

  Bluefruit.Periph.setConnectCallback(connect_callback);
  Bluefruit.Periph.setDisconnectCallback(disconnect_callback);

  // Custom GATT service.
  controlService.begin();

  modeCharacteristic.setProperties(CHR_PROPS_READ | CHR_PROPS_WRITE);
  modeCharacteristic.setPermission(SECMODE_OPEN, SECMODE_OPEN);
  modeCharacteristic.setFixedLen(1);
  modeCharacteristic.setWriteCallback(mode_write_callback);
  modeCharacteristic.begin();
  modeCharacteristic.write8(0);

  // We restart advertising ourselves, with the current mode applied.
  Bluefruit.Advertising.restartOnDisconnect(false);

  startAdvertisingMode(false);
}

// -----------------------------------------------------------------------------
// Main loop
// -----------------------------------------------------------------------------

void loop()
{
  static uint32_t lastPulse = 0;
  static bool ledOn = false;
  const uint32_t now = millis();

  // Apply a pending restart only after the GATT connection is actually gone.
  if (restartAdvertisingPending && !Bluefruit.Periph.connected()) {
    restartAdvertisingPending = false;
    startAdvertisingMode(lostMode);
  }

  // Normal = slow heartbeat, Lost = fast heartbeat.
  const uint32_t period = lostMode ? LOST_LED_PERIOD_MS : NORMAL_LED_PERIOD_MS;

  if (!ledOn && now - lastPulse >= period) {
    lastPulse = now;
    ledOn = true;
    digitalWrite(LED_BUILTIN, LOW);
  } else if (ledOn && now - lastPulse >= LED_PULSE_MS) {
    ledOn = false;
    digitalWrite(LED_BUILTIN, HIGH);
  }

  // Yield to the RTOS instead of busy-spinning; lets the MCU idle between ticks.
  delay(10);
}
