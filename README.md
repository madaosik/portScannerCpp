# ipkproj_2_2019
# Port scanner

Program je napsan v jazyce C++ a zkompilovan a sestaven pomoci prikazu "make" v korenovem adresari.

Prikazem "make run" je provedeno testovaci scanovani na localhostu.

Spusteni:
    ./ipk-scan {-i <interface>} -pu <port-ranges> -pt <port-ranges> [<domain-name> | <IP-address>]

    <interface>                     rozhrani, pres ktere se pripojovat
    <port-ranges>                   porty, ktere chceme scanovat, a to ve formatu seznamu oddeleneho carkami, pripadne rozsahu urceneho pomlckou
                                    Napriklad tedy -pt 21,35,64, pripadne -pu 26-45
    [<domain-name> | <IP-address>]  domenove jmeno nebo IP adresa zarizeni, kde scanovani bude probihat


DULEZITE:
    Vzhledem k neodhalenym nedostatkum v klicovych metodach UdpScanner::scan_port() a TcpScanner::scan_port() (a jejich vstupech) sice program vystup v pozadovanem formatu poskytuje, nicmene neni relevantni.
    Pri testovani pomoci programu Wireshark bylo zjisteno, ze z programu zadne packety neodchazeji, coz ve vysledku znamena, ze vsechny TCP porty jsou oznaceny jako filtrovane a vsechny UDP porty jako otevrene.

    Odesle se tudiz jeden paket, ale odpoved nedorazi, protoze nema kam. Tim padem se odesila druhy paket, ze ktereho opet odpoved nedostavame, a tedy zkoumany port oznacujeme jako filtrovany.
    Analogicka situace je u UDP scanovani - odesilame packety (ve skutecnosti vsak bohuzel neodesilame), takze se nam nema kam pripadne vratit ICMP zprava, ze je port nedostupny. Tudiz vsechny UDP packety jsou oznacene jako otevrene.

    V pripade spravneho odesilani packetu by algoritmy byly schopny dosahnout pozadovaneho vysledku, nicmene to se autorovi nepodarilo.

