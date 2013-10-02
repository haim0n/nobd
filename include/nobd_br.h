#ifndef nobd_BR_H
#define nobd_BR_H

struct net_bridge;

int nobd_br_fdb_init(void);
void nobd_br_fdb_exit(void);
int nobd_br_reg(struct net_bridge *br);
int nobd_br_unreg(struct net_bridge *br);
#endif /* nobd_BR_H */
