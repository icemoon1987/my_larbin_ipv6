// Larbin
// Sebastien Ailleret
// 08-02-00 -> 06-01-02

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "options.h"

#include "types.h"
#include "utils/Fifo.h"
#include "utils/debug.h"
#include "utils/text.h"
#include "utils/connexion.h"
#include "interf/output.h"
#include "fetch/site.h"


/////////////////////////////////////////////////////////
// functions used for the 2 types of sites
/////////////////////////////////////////////////////////

static struct sockaddr_in6 stataddr;

void initSite () {
  stataddr.sin6_family = AF_INET6;
}

/** connect to this addr using connection conn 
 * return the state of the socket
 */
static char getFds (Connexion *conn, struct in6_addr *addr, uint port) {
  memcpy (&stataddr.sin6_addr,
          addr,
          sizeof (struct in6_addr));
  stataddr.sin6_port = htons(port);
  int fd = socket(AF_INET6, SOCK_STREAM, 0);
  if (fd < 0)
    return emptyC;
  else
    global::verifMax(fd);
  conn->socket = fd;
  for (;;) {
    fcntl(fd, F_SETFL, O_NONBLOCK);
    struct sockaddr_in6 *theaddr;
    if (global::proxyAddr != NULL)
      theaddr = global::proxyAddr;
    else
      theaddr = &stataddr;
    if (connect(fd, (struct sockaddr*) theaddr,
                sizeof (struct sockaddr_in6)) == 0) {
      // success
      return writeC;
    } else if (errno == EINPROGRESS) {
      // would block
      return connectingC;
    } else {
      // error
      (void) close(fd);
      return emptyC;
    }
  }
}


///////////////////////////////////////////////////////////
// class NamedSite
///////////////////////////////////////////////////////////

/** Constructor : initiate fields used by the program
 */
NamedSite::NamedSite () {
  name[0] = 0;
  nburls = 0;
  inFifo = 0; outFifo = 0;
  isInFifo = false;
  dnsState = waitDns;
  cname = NULL;
}

/** Destructor : This one is never used
 */
NamedSite::~NamedSite () {
  assert(false);
}

/* Management of the Fifo */
void NamedSite::putInFifo(url *u) {
  fifo[inFifo] = u;
  inFifo = (inFifo + 1) % maxUrlsBySite;
  assert(inFifo!=outFifo);
}

url *NamedSite::getInFifo() {
  assert (inFifo != outFifo);
  url *tmp = fifo[outFifo];
  outFifo = (outFifo + 1) % maxUrlsBySite;
  return tmp;
}

short NamedSite::fifoLength() {
  return (inFifo + maxUrlsBySite - outFifo) % maxUrlsBySite;
}

/* Put an url in the fifo if their are not too many */
void NamedSite::putGenericUrl(url *u, int limit, bool prio) {
  if (nburls > maxUrlsBySite-limit) {
	// Already enough Urls in memory for this Site
    // first check if it can already be forgotten
    if (!strcmp(name, u->getHost())) {
      if (dnsState == errorDns) {
        nburls++;
        forgetUrl(u, noDNS);
        return;
      }
      if (dnsState == noConnDns) {
        nburls++;
        forgetUrl(u, noConnection);
        return;
      }
      if (u->getPort() == port
          && dnsState == doneDns && !testRobots(u->getFile())) {
        nburls++;
        forgetUrl(u, forbiddenRobots);
        return;
      }
    }
    // else put it back in URLsDisk
    refUrl();
    global::inter->getOne();
    if (prio) {
      global::URLsPriorityWait->put(u);
    } else {
      global::URLsDiskWait->put(u);
    }
  } else {
    nburls++;
    if (dnsState == waitDns
        || strcmp(name, u->getHost())
        || port != u->getPort()
        || global::now > dnsTimeout) {
      // dns not done or other site
      putInFifo(u);
      addNamedUrl();
      // Put Site in fifo if not yet in
      if (!isInFifo) {
        isInFifo = true;
        global::dnsSites->put(this);
      }
    } else switch (dnsState) {
    case doneDns:
      transfer(u);
      break;
    case errorDns:
      forgetUrl(u, noDNS);
      break;
    default: // noConnDns
      forgetUrl(u, noConnection);
    }
  }
}

/** Init a new dns query
 */
void NamedSite::newQuery () {
  // test if addr is readable
  /*
  char first_buf[INET6_ADDRSTRLEN];
  //in6_addr addr1;
  memset(first_buf, '1', INET6_ADDRSTRLEN);
  printf("in newQuery, first_buf: %s\n", first_buf);
  inet_ntop(AF_INET6, addr.s6_addr, first_buf, sizeof(first_buf));
  printf("first_buf now: %s\n", first_buf);
  */


  // Update our stats
  newId();
  if (global::proxyAddr != NULL) {
    // we use a proxy, no need to get the sockaddr
    // give anything for going on
    siteSeen();
    siteDNS();
    // Get the robots.txt
    dnsOK();
  } else if (isdigit(name[0])) {
    // the name already in numbers-and-dots notation
	siteSeen();
	if (inet_pton(AF_INET6, name, &addr.s6_addr)) {
	  // Yes, it is in numbers-and-dots notation
	  siteDNS();
	  // Get the robots.txt
	  dnsOK();
	} else {
	  // No, it isn't : this site is a non sense
      dnsState = errorDns;
	  dnsErr();
	}
  } else {
    // submit an adns query
    printf("in newQuery. Name: %s\n",name);
    global::nbDnsCalls++;
    adns_query quer = NULL;
    adns_submit(global::ads, name,
                (adns_rrtype) adns_r_aaaa,
                (adns_queryflags) 0,
                  NULL, &quer);
    printf("in newQuery()\n");
    // test if addr is readable
  
    char first_buf[INET6_ADDRSTRLEN];
    //in6_addr addr1;
    memset(first_buf, '1', INET6_ADDRSTRLEN);
    printf("in newQuery, first_buf: %s\n", first_buf);
    inet_ntop(AF_INET6, addr.s6_addr, first_buf, sizeof(first_buf));
    printf("first_buf now: %s\n", first_buf);
  }
}

/** The dns query ended with success
 * assert there is a freeConn
 */
void NamedSite::dnsAns (adns_answer *ans) {
  /*
  // test if addr is readable
  // the result: segementation fault 
  char first_buf[INET6_ADDRSTRLEN];
  //in6_addr addr1;
  memset(first_buf, '1', INET6_ADDRSTRLEN);
  printf("in dnsAns, first_buf: %s\n", first_buf);
  inet_ntop(AF_INET6, addr.s6_addr, first_buf, sizeof(first_buf));
  printf("first_buf now: %s\n", first_buf);
  */

  if (ans->status == adns_s_prohibitedcname) {
    printf("ans->status == adns_s_prohibitedcname == %d\n", ans->status);
    if (cname == NULL && ans->cname != NULL) {
      // try to find ip for cname of cname
      printf("cname == NULL\n");
      printf("ans->cname: %s\n", ans->cname);
      printf("ans->owner: %s\n", ans->owner);
      //printf("ans.addr: %s\n", inet_ntoa(ans->rrs.addr->addr.inet.sin6_addr));
      cname = newString(ans->cname);
      printf("after cname = newString(ans->cname)\n");
      global::nbDnsCalls++;
      adns_query quer = NULL;
      adns_submit(global::ads, cname,
                  (adns_rrtype) adns_r_aaaa,
                  (adns_queryflags) 0,
                  this, &quer);
    } else {
      // dns chains too long => dns error
      // cf nslookup or host for more information
      siteSeen();
      printf("cname != NULL\n");
      delete [] cname; cname = NULL;
      dnsState = errorDns;
      dnsErr();
    }
  } else {
    printf("in dnsAns and ans->status is not eque to adns_s_prohibitedcname\n");
    if (ans->status != adns_s_ok) {
    // No addr inet
        printf("ans->status != adns_s_ok\n");
        dnsState = errorDns;
        dnsErr();
    } else {
        siteDNS();
        char buf[INET6_ADDRSTRLEN] = "";
        printf("ans->status == adns_s_ok == %d\n", ans->status);
        printf("ans->cname: %s\n", ans->cname);
        printf("ans->owner: %s\n", ans->owner);
        // compute the new addr
        inet_ntop(AF_INET6, ans->rrs.in6addr, buf, INET6_ADDRSTRLEN);
        printf("ans->rrs.in6addr ip: %s\n", buf);
        
        //printf("sizeof(struct in6_addr): %ld\n", sizeof(struct in6_addr));
        //printf("INET6_ADDRSTRLEN: %ld\n", INET6_ADDRSTRLEN);

        //struct in6_addr addr1;
        //memcpy(&addr1, ans->rrs.in6addr, sizeof(struct in6_addr));
        
        memcpy(&addr, ans->rrs.in6addr, sizeof(struct in6_addr));
        memset(buf, '0', sizeof(buf));
        printf("buf: %s\n", buf);
        inet_ntop(AF_INET6, addr.s6_addr, buf, sizeof(buf));
        printf("addr.s6_addr: %s\n", buf);
        printf("after memcpy in dnsAns\n");
     }
    }
    // Get the robots.txt
    dnsOK();
}

/** we've got a good dns answer
 * get the robots.txt
 * assert there is a freeConn
 */
void NamedSite::dnsOK () {
  Connexion *conn = global::freeConns->get();
  char res = getFds(conn, &addr, port);
  if (res != emptyC) {
    printf("in dnsOK and getFds is not emptyC\n");
    conn->timeout = timeoutPage;
    if (global::proxyAddr != NULL) {
      // use a proxy
      conn->request.addString("GET http://");
      conn->request.addString(name);
      char tmp[15];
      sprintf(tmp, ":%u", port);
      conn->request.addString(tmp);
      conn->request.addString("/robots.txt HTTP/1.0\r\nHost: ");
    } else {
      // direct connection
      conn->request.addString("GET /robots.txt HTTP/1.0\r\nHost: ");
    }
    conn->request.addString(name);
    conn->request.addString(global::headersRobots);
    conn->parser = new robots(this, conn);
    conn->pos = 0;
    conn->err = success;
    conn->state = res;
  } else {
    printf("in dnsOK and getFds is emptyC\n");
    // Unable to get a socket
    global::freeConns->put(conn);
    dnsState = noConnDns;
    dnsErr();
  }
}

/** Cannot get the inet addr
 * dnsState must have been set properly before the call
 */
void NamedSite::dnsErr () {
  FetchError theErr;
  if (dnsState == errorDns) {
    theErr = noDNS;
  } else {
    theErr = noConnection;
  }
  int ss = fifoLength();
  // scan the queue
  for (int i=0; i<ss; i++) {
    url *u = getInFifo();
    if (!strcmp(name, u->getHost())) {
      delNamedUrl();
      forgetUrl(u, theErr);
    } else { // different name
      putInFifo(u);
    }
  }
  // where should now lie this site
  if (inFifo==outFifo) {
    isInFifo = false;
  } else {
    global::dnsSites->put(this);
  }
}

/** test if a file can be fetched thanks to the robots.txt */
bool NamedSite::testRobots(char *file) {
  uint pos = forbidden.getLength();
  for (uint i=0; i<pos; i++) {
    if (robotsMatch(forbidden[i], file))
      return false;
  }
  return true;
}

/** Delete the old identity of the site */
void NamedSite::newId () {
  // ip expires or new name or just new port
  // Change the identity of this site
#ifndef NDEBUG
  if (name[0] == 0) {
    addsite();
  }
#endif // NDEBUG
  url *u = fifo[outFifo];
  strcpy(name, u->getHost());
  port = u->getPort();
  dnsTimeout = global::now + dnsValidTime;
  dnsState = waitDns;
}

/** we got the robots.txt,
 * compute ipHashCode
 * transfer what must be in IPSites
 */
void NamedSite::robotsResult (FetchError res) {
  bool ok = res != noConnection;
  if (ok) {
    dnsState = doneDns;
    // compute ip hashcode
    if (global::proxyAddr == NULL) {
      ipHash=0;
      char *s = (char *) &addr;
      for (uint i=0; i<sizeof(struct in6_addr); i++) {
        ipHash = ipHash*31 + s[i];
      }
    } else {
      // no ip and need to avoid rapidFire => use hostHashCode
      ipHash = this - global::namedSiteList;
    }
    ipHash %= IPSiteListSize;
  } else {
    dnsState = noConnDns;
  }
  int ss = fifoLength();
  // scan the queue
  for (int i=0; i<ss; i++) {
    url *u = getInFifo();
    if (!strcmp(name, u->getHost())) {
      delNamedUrl();
      if (ok) {
        if (port == u->getPort()) {
          transfer(u);
        } else {
          putInFifo(u);
        }
      } else {
        forgetUrl(u, noConnection);
      }
    } else {
      putInFifo(u);
    }
  }
  // where should now lie this site
  if (inFifo==outFifo) {
    isInFifo = false;
  } else {
    global::dnsSites->put(this);
  }  
}

void NamedSite::transfer (url *u) {
  if (testRobots(u->getFile())) {
    if (global::proxyAddr == NULL) {
      memcpy (&u->addr, &addr, sizeof (struct in6_addr));
    }
    global::IPSiteList[ipHash].putUrl(u);
  } else {
    forgetUrl(u, forbiddenRobots);
  }
}

void NamedSite::forgetUrl (url *u, FetchError reason) {
  urls();
  fetchFail(u, reason);
  answers(reason);
  nburls--;
  delete u;
  global::inter->getOne();
}

///////////////////////////////////////////////////////////
// class IPSite
///////////////////////////////////////////////////////////

/** Constructor : initiate fields used by the program
 */
IPSite::IPSite () {
  lastAccess = 0;
  isInFifo = false;
}

/** Destructor : This one is never used
 */
IPSite::~IPSite () {
  assert(false);
}

/** Put an prioritarian url in the fifo
 * Up to now, it's very naive
 * because we have no memory of priority inside the url
 */
void IPSite::putUrl (url *u) {
  // All right, put this url inside at the end of the queue
  tab.put(u);
  addIPUrl();
  // Put Site in fifo if not yet in
  if (!isInFifo) {
#ifndef NDEBUG
    if (lastAccess == 0) addipsite();
#endif // NDEBUG
    isInFifo = true;
    if (lastAccess + global::waitDuration <= global::now
        && global::freeConns->isNonEmpty()) {
      fetch();
    } else {
      global::okSites->put(this);
    }
  }
}

/** Get an url from the fifo and do some stats
 */
inline url *IPSite::getUrl () {
  url *u = tab.get();
  delIPUrl();
  urls();
  global::namedSiteList[u->hostHashCode()].nburls--;
  global::inter->getOne();
#if defined(SPECIFICSEARCH) && !defined(NOSTATS)
  if (privilegedExts[0] != NULL && matchPrivExt(u->getFile())) {
    extensionTreated();
  }
#endif
  return u;
}

/** fetch the first page in the fifo okSites
 * there must be at least one element in freeConns !!!
 * return expected time for next call (0 means now is OK)
 * This function always put the IPSite in fifo before returning
 *   (or set isInFifo to false if empty)
 */
int IPSite::fetch () {
  if (tab.isEmpty()) {
	// no more url to read
	// This is possible because this function can be called recursively
	isInFifo = false;
    return 0;
  } else {
    int next_call = lastAccess + global::waitDuration;
    if (next_call > global::now) {
      global::okSites->rePut(this);
      return next_call;
    } else {
      Connexion *conn = global::freeConns->get();
      url *u = getUrl();
      // We're allowed to fetch this one
      // open the socket and write the request
      char res = getFds(conn, &(u->addr), u->getPort());
      if (res != emptyC) {
        lastAccess = global::now;
        conn->timeout = timeoutPage;
        conn->request.addString("GET ");
        if (global::proxyAddr != NULL) {
          char *tmp = u->getUrl();
          conn->request.addString(tmp);
        } else {
          conn->request.addString(u->getFile());
        }
        conn->request.addString(" HTTP/1.0\r\nHost: ");
        conn->request.addString(u->getHost());
#ifdef COOKIES
        if (u->cookie != NULL) {
          conn->request.addString("\r\nCookie: ");
          conn->request.addString(u->cookie);
        }
#endif // COOKIES
        conn->request.addString(global::headers);
        conn->parser = new html (u, conn);
        conn->pos = 0;
        conn->err = success;
        conn->state = res;
        if (tab.isEmpty()) {
          isInFifo = false;
        } else {
          global::okSites->put(this);
        }
        return 0;
      } else {
        // Unable to connect
        fetchFail(u, noConnection);
        answers(noConnection);
        delete u;
        global::freeConns->put(conn);
        return fetch();
      }    
    }
  }
}
