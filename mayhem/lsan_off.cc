// Disable LeakSanitizer at build time (ASan/UBSan stay on and halting).
extern "C" int __lsan_is_turned_off() { return 1; }
