///Sourced from https://gist.githubusercontent.com/deltheil/2321409/raw/e83ed965923314bd21bcfa984266e5dc2dd8d9b0/systemversion.c

#include <objc/runtime.h>
#include <objc/message.h>
#include <CoreFoundation/CoreFoundation.h>

/* ... */

/**
 * Return a character string that holds the current version
 * of the operating system which is equivalent to:
 * `[[UIDevice currentDevice] systemVersion]`
 * in plain Obj-C code.
 * The caller must manage deletion.
 */
char *getsystemversion(void) {
  char *sv = NULL;
  id Dev = objc_msgSend(objc_getClass("UIDevice"), sel_getUid("currentDevice"));
  CFStringRef SysVer = (CFStringRef) objc_msgSend(Dev, sel_getUid("systemVersion"));
  CFIndex len = CFStringGetLength(SysVer);
  CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
  sv = (char *) malloc(max + 1);
  CFStringGetCString(SysVer, sv, max, kCFStringEncodingUTF8);
  return sv;
}
