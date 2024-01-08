#include "dlfcn.h"
#include "pkcs11.h"
#include "stdio.h"
#include "unistd.h"
#include "sys/wait.h"


int main() {
  void *handle = dlopen("../target/release/libnethsm_pkcs11.so", RTLD_LAZY)  ;
  if (!handle) {
    fprintf(stderr, "%s\n", dlerror());
    return 1;
  }
  dlerror();


  CK_C_GetFunctionList c_get_function_list = dlsym(handle, "C_GetFunctionList");

  char * error = dlerror();
  if (error != NULL) {
    fprintf(stderr, "%s\n", error);
    return 1;
  }

  struct _CK_FUNCTION_LIST *flist;
  c_get_function_list(&flist);

  flist->C_Initialize(NULL);

  pid_t p = fork(); 
  if (p < 0) {
    perror("Fork failed");
    return 1;
  }

  int wstatus = 0;
  if (p == 0 ) {
    flist->C_Initialize(NULL);
    CK_SLOT_ID slotId = CK_UNAVAILABLE_INFORMATION;
    CK_SESSION_HANDLE session;
    CK_RV rv = flist->C_OpenSession(0,CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
      printf("Failed open session: %lu", rv);
    }

    unsigned char random[8];
    rv = flist->C_GenerateRandom(session, random, 8);
    if (rv != CKR_OK) {
      printf("Failed get random: %lu", rv);
    }
    return 0;
  } else {
    wait(&wstatus);
    return WEXITSTATUS(wstatus);
  }
}
