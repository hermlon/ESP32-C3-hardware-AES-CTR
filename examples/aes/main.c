#include <mdk.h>

int main(void) {
	wdt_disable();

  for (;;) {
		printf("test: %d -> %d\n", 0, 0);
    delay_ms(10);
  }

  return 0;
}
