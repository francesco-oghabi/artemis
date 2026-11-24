# Dizionari per `hash_crack`

Il tool `hash_crack` (crack MD5 offline) usa, in unione:

1. un **dizionario di default embedded** nel binario (`agent/wordlists/common.txt`,
   password più comuni): zero-config;
2. ogni file **`*.txt`** presente nella **directory dizionari utente**;
3. parole passate **inline** al tool (parametro `wordlist`).

## Directory dizionari utente

Default: **`data/wordlists/`** relativa alla working dir del processo (nel container
è `/app/data/wordlists/`, dentro il volume dati, quindi **persiste** tra i riavvii).
Override con la variabile d'ambiente **`ARTEMIS_WORDLISTS_DIR`**.

Per aggiungere un dizionario: copiare un file `.txt` (una password per riga, righe
che iniziano con `#` ignorate) nella directory. Esempio nel container:

    docker cp rockyou.txt artemis-artemis-1:/app/data/wordlists/

I dizionari sono riusabili in qualsiasi task/contesto, non solo per il benchmark.

## Stato

Oggi solo **MD5 unsalted**. In roadmap: SHA1/SHA256, hash salati (richiede il salt),
e bcrypt (lento, da gestire fuori dal loop agentico).
