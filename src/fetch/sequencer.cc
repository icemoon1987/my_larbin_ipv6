// Larbin
// Sebastien Ailleret
// 15-11-99 -> 04-01-02

#include <iostream.h>

#include "options.h"

#include "global.h"
#include "types.h"
#include "utils/url.h"
#include "utils/debug.h"
#include "fetch/site.h"

static bool canGetUrl (bool *testPriority);
uint space = 0;

#define maxPerCall 100

/** start the sequencer
 */
void sequencer () {
  bool testPriority = true;
  if (space == 0) {
    space = global::inter->putAll();
  }
  int still = space;
  if (still > maxPerCall) still = maxPerCall;
  while (still) {
    if (canGetUrl(&testPriority)) {
      space--; still--;
    } else {
      still = 0;
    }
  }
}

/* Get the next url
 * here is defined how priorities are handled
 */
static bool canGetUrl (bool *testPriority) {
  url *u;
  if (global::readPriorityWait) {
    printf("in sequencer and global::readPriorityWait\n");
    global::readPriorityWait--;
    u = global::URLsPriorityWait->get();
    global::namedSiteList[u->hostHashCode()].putPriorityUrlWait(u);
    return true;
  } else if (*testPriority && (u=global::URLsPriority->tryGet()) != NULL) {
    printf("in sequencer and URLsPriority->tryGet() not NULL\n");
    // We've got one url (priority)
    global::namedSiteList[u->hostHashCode()].putPriorityUrl(u);
    return true;
  } else {
    *testPriority = false;
    // Try to get an ordinary url
    if (global::readWait) {
      printf("in sequencer and readWait\n");
      global::readWait--;
      u = global::URLsDiskWait->get();
      global::namedSiteList[u->hostHashCode()].putUrlWait(u);
      return true;
    } else {
      u = global::URLsDisk->tryGet();
      printf("in sequencer and URLsDisk and u: ");
      if (u != NULL) {
        global::namedSiteList[u->hostHashCode()].putUrl(u);
        u->print();
        printf("u->hostHashCode: %ld\n", u->hostHashCode());
        printf("u->hostHashCode: %ld\n", u->hostHashCode());
        return true;
      } else {
        return false;
      }
    }
  }
}
