# Dataplane-Router


Gheorghe Marius Razvan 324 CA


Punctul de plecare al temei a fost laboratorul 4 adica partea de ipv4.

Am implementat procesul de dirijare, longest prefix match si protocolul icmp, doar arp static.

1.Procesul de dirijare:
Verific daca checksum ul ip este corect pentru a determina 
daca pachetul este corupt sau nu.
Daca pachetul este destinat routerului si este echo request trimite un echo
reply.
Caut cea mai buna routa pentru destinatia pachetului iar daca nu gasesc
trimit un icmp de tip destination unreachable.
Decrementez ttl u si daca ajunge la 0 inainte sa il trimit 
voi proceda cu icmp time exceeded.
Apoi actualizez adresele mac adica sursa si destinatie si trimit pachetul.
2.LPM
Folosesc o cautare eficienta cu complexitate O(logn), cautarea binara iar
inainte de aceasta sortez tabela de rutare pentru a fi si mai eficient 
3.ICMP
Schimb intre ele adresele ip sursa cu ip destinatie ale pachetului
Resetez ttl ul,setez lungimea totala a pachetului pentru a cuprinde headerul
ip si cel icmp si reactualizez checksum ul headerului ip.
Setez type pentru icmp (echo reply etc).
Fac o inversare a adreselor MAC si apoi trimit pachetul prin interfata initiala.
