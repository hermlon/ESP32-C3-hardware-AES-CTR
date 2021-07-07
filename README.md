# ESP32 SDK

An alternative, make-based, bare metal SDK for the ESP32, ESP32C3 chips.
It is written from scratch using datasheets (
[ESP32 C3 TRM](https://www.espressif.com/sites/default/files/documentation/esp32-c3_technical_reference_manual_en.pdf),
[ESP32 TRM](https://www.espressif.com/sites/default/files/documentation/esp32_technical_reference_manual_en.pdf)
).
It is completely independent from the ESP-IDF and does not use any
ESP-IDF tools or files. The only tool required is a GCC crosscompiler.

A screenshot below demonstrates a [examples/c3ws2812](examples/c3ws2812)
RGB LED firmware flashed on a ESP32-C3-DevKitM-1 board. It takes < 2 seconds
for a full firmware rebuild and flash:

![](examples/c3ws2812/rainbow.gif)

# Environment setup

Required tools: 
- MacOS or Linux operating system
- For ESP32C3, install a 32-bit riscv GCC crosscompiler:
   - MacOS (takes time):
      ```sh
      $ brew tap riscv/riscv
      $ brew install riscv-gnu-toolchain --with-multilib
      ```
   - Linux:
      ```sh
      $ sudo apt-get install -y gcc-riscv64-linux-gnu
      ```
- For ESP32, a 32-bit xtensa-esp32-elf-gcc crosscompiler is required,
  make sure it is in the PATH

Export the following environment variables:

```sh
$ export ARCH=ESP32C3          # Choices: ESP32C3, ESP32
$ export PORT=/dev/ttyUSB0     # Serial port for flashing
```

Verify setup by building and flashing a blinky example firmware.
From repository root, execute:

```sh
$ make -C examples/blinky clean build flash monitor
```

# Firmware Makefile

Firmware Makefile should look like this:

```make
SOURCES = main.c another_file.c

EXTRA_CFLAGS ?=
EXTRA_LINKFLAGS ?=

include $(SDK_PATH)/make/build.mk
```

# Environment reference

Environment / Makefile variables:

| Name | Description |
| ---- | ----------- |
| ARCH | Architecture. Possible values: ESP32C3, ESP32. Default: ESP32C3 |
| TOOLCHAIN | GCC binary prefix. Default: for ESP32C3: riscv64-unknown-elf; for ESP32: xtensa-esp32-elf  |
| PORT | Serial port. Default: /dev/ttyUSB0 |
| EXTRA\_CFLAGS | Extra compiler flags. Default: empty |
| EXTRA\_LINKFLAGS | Extra linker flags. Default: empty |

Makefile targets:

| Name | Description | 
| ---- | ----------- |
| clean | Clean up build artifacts |
| build | Build firmware in a project's `build/` directory |
| flash | Flash firmware. Needs PORT variable set |
| monitor | Run serial monitor. Needs PORT variable set |
| unix | Build Mac/Linux executable firmware, see "UNIX mode" section below |


Preprocessor definitions

| Name | Description | 
| ---- | ----------- |
| LED1 | User LED pin. Default: 2 |
| BTN1 | User button pin. Default: 9 |


# API reference

API support matrix:

| Name    | GPIO | SPI | I2C | UART | WiFi | Timer | System | RTOS |
| ----    | ---- | --- | --- | ---- | ---- | ----- | ------ | ---- |
| ESP32C3 | yes  | yes |  -  |  yes |  -   |  yes  |  yes   | -    |
| ESP32   | yes  | yes |  -  |  -   |  -   |  yes  |  yes   | -    |

- GPIO [[src/gpio.h](src/gpio.h)]
  ```c
  void gpio_output(int pin);              // Set pin mode to OUTPUT
  void gpio_input(int pin);               // Set pin mode to INPUT
  void gpio_write(int pin, bool value);   // Set pin to low (false) or high
  void gpio_toggle(int pin);              // Toggle pin value
  bool gpio_read(int pin);                // Read pin value
  ```
- SPI [[src/spi.h](src/spi.h)]
  ```c
  // SPI descriptor. Specifies pins for MISO, MOSI, CLK and chip select
  struct spi { int miso, mosi, clk, cs[3]; };

  bool spi_init(struct spi *spi);           // Init SPI
  void spi_begin(struct spi *spi, int cs);  // Start SPI transaction
  void spi_end(struct spi *spi, int cs);    // End SPI transaction
  unsigned char spi_txn(struct spi *spi, unsigned char);   // Do SPI transaction
  ```
- UART [[src/uart.h](src/uart.h)], [[src/uart.c](src/uart.c)]
  ```c
  void uart_init(int no, int tx, int rx, int baud);   // Initialise UART
  bool uart_read(int no, uint8_t *c);   // Read byte. Return true on success
  void uart_write(int no, uint8_t c);   // Write byte. Block if FIFO is full
  ```
- LEDC
- WDT [[src/wdt.h](src/wdt.h)]
  ```c
  void wdt_disable(void);   // Disable watchdog
  ```
- Timer [[src/timer.h](src/timer.h)]
  ```c
  struct timer {
    uint64_t period;       // Timer period in micros
    uint64_t expire;       // Expiration timestamp in micros
    void (*fn)(void *);    // Function to call
    void *arg;             // Function argument
    struct timer *next;    // Linkage
  };

  #define TIMER_ADD(head_, p_, fn_, arg_)
  void timers_poll(struct timer *head, uint64_t now);
  ```
- System  [[src/sys.h](src/sys.h)]
  ```c
  int sdk_ram_used(void);           // Return used RAM in bytes
  int sdk_ram_free(void);           // Return free RAM in bytes
  unsigned long time_us(void);      // Return uptime in microseconds
  void delay_us(unsigned long us);  // Block for "us" microseconds
  void delay_ms(unsigned long ms);  // Block for "ms" milliseconds
  void spin(unsigned long count);   // Execute "count" no-op instructions
  ```
- Log [[src/log.h](src/log.h)], [[src/log.c](src/log.c)]
  ```c
  void sdk_log(const char *fmt, ...);   // Log message to UART 0
                                        // Supported specifiers:
                                        // %d, %x, %s, %p
  void sdk_hexdump(const void *buf, size_t len);  // Hexdump buffer
  ```
- TCP/IP


# UNIX mode

Firmware examples could be built on Mac/Linux as normal UNIX binaries.
In the firmware directory, type

```sh
make unix
```

That builds a `build/firmware` executable.
To support that, all hardware API are mocked out. The typical API
implementation looks like:

```c
#if defined(ESP32C3)
...
#elif defined(ESP32)
...
#elif defined(__unix) || defined(__unix__) || defined(__APPLE__)
...  <-- Here goes a mocked-out hardware API implementation
#endif
```
