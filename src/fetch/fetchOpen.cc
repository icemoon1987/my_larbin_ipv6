// Larbin
// Sebastien Ailleret
// 15-11-99 -> 04-12-01

#include <iostream.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <adns.h>

#include "options.h"

#include "global.h"
#include "utils/Fifo.h"
#include "utils/debug.h"
#include "fetch/site.h"

/* Opens sockets
 * Never block (only opens sockets on already known sites)
 * work inside the main thread
 */
void fetchOpen () {
  static time_t next_call = 0;
  if (global::now < next_call) { // too early to come back
    return;
  }
  int cont = 1;
  while (cont && global::freeConns->isNonEmpty()) {
    IPSite *s = global::okSites->tryGet();
    if (s == NULL) {
      cont = 0;
    } else {
      next_call = s->fetch();
      cont = (next_call == 0);
    }
  }
}

/* Opens sockets
 * this function perform dns calls, using adns
 */
void fetchDns () {
  // Submit queries
  while (global::nbDnsCalls<global::dnsConn
         && global::freeConns->isNonEmpty()
         && global::IPUrl < maxIPUrls) { // try to avoid too many dns calls
    NamedSite *site = global::dnsSites->tryGet();
    if (site == NULL) {
      break;
    } else {
      //printf("before newQuery\n");
      site->newQuery();
      //printf("after newQuery\n");
    }
  }

  // Read available answers
  while (global::nbDnsCalls && global::freeConns->isNonEmpty()) {
    NamedSite *site;
    adns_query quer = NULL;
    adns_answer *ans;
    int res = adns_check(global::ads, &quer, &ans, (void**)&site);
    if (res == ESRCH || res == EAGAIN) {
      // No more query or no more answers
      break;
    }
    global::nbDnsCalls--;
    printf("ans->cname: %s\n", ans->cname);
    printf("ans->owner: %s\n", ans->owner);
    //printf("ans.addr: %s\n", inet_ntoa(ans->rrs.addr->addr.inet.sin_addr));
    printf("before dnsAns\n");
    site->dnsAns(ans);
    printf("after dnsAnds\n\n");
    free(ans); // ans has been allocated with malloc
  }
}
