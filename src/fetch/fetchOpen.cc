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
  printf("in fetchOpen\n");
  static time_t next_call = 0;
  if (global::now < next_call) { // too early to come back
    return;
  }
  int cont = 1;
  while (cont && global::freeConns->isNonEmpty()) {
    IPSite *s = global::okSites->tryGet();
    if (s == NULL) {
      cont = 0;
      printf("in fetchOpen and s == NULL the cont = %d\n", cont);
    } else {
      printf("in fetchOpen and before next_call = s->fetch\n");
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
      printf("before newQuery\n");
      site->newQuery();
      printf("after newQuery\n");

      // to test whether addr is readable
      // here site->addr.s6_addr is readable
      char buf[INET6_ADDRSTRLEN];
      memset(buf, '2', sizeof(buf));
      printf("in fetchDns(), buf: %s\n", buf);
      inet_ntop(AF_INET6, site->addr.s6_addr, buf, sizeof(buf));
      printf("now buf: %s\n", buf);
    }
  }

  // Read available answers
  while (global::nbDnsCalls && global::freeConns->isNonEmpty()) {
    NamedSite *site;
    adns_query quer = NULL;
    adns_answer *ans;
    char buf[INET6_ADDRSTRLEN];

    // to test whether addr is readable
    // here site->addr.s6_addr is readable
    memset(buf, '3', sizeof(buf));
    printf("in fetchDns and before adns_check, buf: %s\n", buf);
    inet_ntop(AF_INET6, site->addr.s6_addr, buf, sizeof(buf));
    printf("now buf: %s\n", buf);

    //int res = adns_check(global::ads, &quer, &ans, (void**)&site);
    int res = adns_check(global::ads, &quer, &ans, NULL);

    // to test whether addr is readable
    // segmentation fault
    memset(buf, '0', sizeof(buf));
    printf("in fetchDns and after adns_check, buf: %s\n", buf);
    memcpy(site->addr.s6_addr, buf, sizeof(buf));
    inet_ntop(AF_INET6, site->addr.s6_addr, buf, sizeof(buf));
    printf("now buf: %s\n", buf);

    if (res == ESRCH || res == EAGAIN) {
      // No more query or no more answers
      break;
    }
    global::nbDnsCalls--;
    printf("in fetchDns(): ans->cname: %s\n", ans->cname);
    printf("in fetchDns(): ans->owner: %s\n", ans->owner);
    inet_ntop(AF_INET6, ans->rrs.in6addr, buf, INET6_ADDRSTRLEN);
    printf("in fetchDns(): ans->rrs.in6addr: %s\n", buf);
    printf("before dnsAns\n");
    site->dnsAns(ans);
    printf("after dnsAnds\n\n");
    free(ans); // ans has been allocated with malloc
  }
}
