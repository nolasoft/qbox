#include "../guest/workspace.h"
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  int result = !strcmp(argv[1], "import")
      ? qbox_workspace_import(argv[2], argv[3], getuid(), getgid(), 1024 * 1024)
      : qbox_workspace_export(argv[2], argv[3], NULL, 1024 * 1024);
  return result ? 1 : 0;
}
