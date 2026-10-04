// Same probe, with success inverted. Pass a numeric destination to distinguish
// packet denial from a missing guest DNS mapping.
#define main allowed_probe
#define QBOX_TCP_ONLY
#include "net_allowed.c"
#undef main
int main(int argc, char **argv) {
  int result = allowed_probe(argc, argv);
  if (result == 2)
    return 2;
  return result == 0 ? 1 : 0;
}
