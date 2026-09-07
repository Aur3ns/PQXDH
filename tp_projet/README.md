# Dossier maître — TP de cryptographie appliquée

> Document de transmission exhaustif pour transformer le dépôt PQXDH en rendu
> complet du sujet 5 : « Créer une messagerie sécurisée utilisant des
> algorithmes postquantiques ».

## 0. Mode d'emploi de ce document

Ce fichier est la source de vérité pour la partie TP du projet. Il est conçu
pour être lu aussi bien par les étudiants que par un nouvel assistant de code
qui ne disposerait d'aucun historique de conversation.

Si vous êtes un assistant chargé de poursuivre le travail :

1. ouvrez le dépôt à sa racine ;
2. lisez ce fichier entièrement avant de modifier quoi que ce soit ;
3. lisez ensuite `README.md`, `docs/PROTOCOL.md`, `SECURITY.md`, `pqxdh.h`,
   `pqxdh.c`, `test_pqxdh.c` et `CMakeLists.txt` ;
4. initialisez et inspectez les sous-modules `liboqs` et `libxeddsa` ;
5. vérifiez l'état Git et ne détruisez aucun changement existant ;
6. confrontez chaque changement cryptographique aux sources primaires ;
7. ne prétendez jamais qu'une propriété est garantie sans annoncer le modèle
   d'attaquant et les hypothèses nécessaires ;
8. ne recodez aucune primitive cryptographique ;
9. ajoutez des tests et une entrée d'audit pour chaque changement sensible ;
10. gardez ce document à jour au fur et à mesure des décisions.

Ce document décrit à la fois :

- les consignes scolaires applicables ;
- l'état réel du dépôt au début du TP ;
- le périmètre recommandé ;
- les propriétés de sécurité ;
- l'architecture Android et Bluetooth envisagée ;
- le protocole expérimental ;
- les mesures attendues ;
- l'audit obligatoire du code assisté par IA ;
- le plan du rapport ;
- la feuille de route et les critères d'acceptation.

Il ne remplace ni le rapport final ni les sources primaires.

---

## 1. Contexte administratif

### 1.1 Intitulé

- Enseignement : Atelier/TP de Cryptographie appliquée.
- Année : 2026.
- Sujet retenu : sujet 5, messagerie sécurisée utilisant des algorithmes
  postquantiques.
- Travail autorisé : seul ou en binôme, jamais en groupe de trois.
- Date limite annoncée : lundi 7 décembre 2026 à 08:00.
- L'horodatage pris en compte est celui du dernier commit poussé sur la branche
  par défaut du GitLab de l'école.

### 1.2 Lieu de rendu

Le rendu officiel doit être placé dans un dépôt unique sur le GitLab de
l'école. Le dépôt GitHub `Aur3ns/PQXDH` peut rester un dépôt de développement ou
un miroir, mais il ne remplace pas le GitLab demandé.

À faire suffisamment tôt :

- créer le projet GitLab de l'équipe ;
- ajouter le remote GitLab sans supprimer le remote GitHub ;
- vérifier que les sous-modules sont accessibles depuis l'environnement de
  correction ;
- configurer une branche par défaut explicite ;
- tester un clone récursif anonyme depuis une machine vierge ;
- ajouter une CI GitLab ;
- pousser le PDF final avant l'échéance ;
- vérifier le commit effectivement visible sur la branche par défaut.

### 1.3 Livrables obligatoires

L'absence d'un seul des trois livrables suivants plafonne la note :

1. un rapport écrit au format PDF présentant démarche, résultats et
   interprétation ;
2. le code et sa documentation, relançables sur une machine vierge ;
3. les statistiques des données utilisées pour conclure : volume, distribution,
   contenu et limites du jeu de données.

Pour ce sujet, les « données » sont principalement les résultats des campagnes
de benchmarks et de tests réseau. Il faut conserver :

- les scripts qui génèrent les expériences ;
- les métadonnées de la machine et des versions ;
- les résultats bruts si leur taille reste raisonnable ;
- les statistiques agrégées ;
- les scripts de génération des tableaux et graphiques ;
- une explication claire de ce qui a été mesuré et de ce qui ne l'a pas été.

Ne pas mettre de données volumineuses inutiles dans Git. Si un jeu devient trop
gros, conserver les scripts et expliquer comment le reconstruire.

### 1.4 Barème

| Critère | Points | Conséquence pratique |
| --- | ---: | --- |
| Problématique et périmètre | 3 | Poser une question mesurable et annoncer les exclusions |
| État de l'art et sources | 3 | Utiliser et discuter des sources primaires |
| Méthode et protocole expérimental | 5 | Permettre une reproduction indépendante complète |
| Résultats et analyse | 5 | Répéter, montrer la dispersion et interpréter |
| Rigueur cryptographique | 2 | Faire correspondre code, protocole, version et rapport |
| Forme et reproductibilité | 2 | PDF lisible, dépôt propre, commande simple |
| **Total** | **20** | |

### 1.5 Causes explicites de perte de points

- Si le code n'implémente pas la version annoncée, la partie concernée vaut
  zéro.
- Une mesure sans protocole reproductible ne rapporte aucun point.
- Une affirmation de sécurité sans modèle d'attaquant explicite ne rapporte
  aucun point.
- Les captures d'écran de terminal sont pénalisées ; utiliser du texte avec une
  typographie adaptée.
- Un code correct mais incompris ne rapporte pas les points d'audit attendus.
- Un usage d'assistant de génération non déclaré est traité comme une fraude.

### 1.6 Usage de l'intelligence artificielle

L'usage de Codex est autorisé mais doit être déclaré précisément. Le code
cryptographique produit ou modifié avec cette assistance doit être audité ligne
par ligne par les étudiants. L'audit, les défauts trouvés et les corrections
doivent apparaître dans le rapport.

Il ne suffit pas d'écrire « le code a été relu ». Il faut fournir une trace :

- zone ou fonction auditée ;
- objectif de cette zone ;
- source normative correspondante ;
- invariants vérifiés ;
- erreurs envisagées ;
- tests associés ;
- défauts trouvés ;
- corrections appliquées ;
- limites restantes.

---

## 2. Texte opérationnel du sujet 5

Le rendu doit répondre à quatre blocs.

### 2.1 État de l'art des primitives

À partir des publications du NIST et des implémentations de référence :

- décrire les primitives postquantiques normalisées ;
- expliquer leur fonction et leurs paramètres ;
- présenter les bibliothèques qui les fournissent ;
- ne pas recoder les primitives ;
- concentrer le travail d'implémentation sur le protocole.

### 2.2 Propriétés visées

La messagerie doit :

- authentifier les correspondants ;
- garantir la confidentialité des messages ;
- alerter les utilisateurs si des messages sont « interceptés ».

Chaque phrase doit être traduite en propriété de sécurité explicite avant
l'implémentation. Pour l'alerte, il faut préciser l'événement réellement
détecté et les hypothèses faites sur l'attaquant.

### 2.3 Établissement de clé hybride

L'établissement doit combiner :

- une primitive classique ;
- une primitive postquantique ;
- une méthode de combinaison justifiée ;
- une argumentation conforme à la position de l'ANSSI.

Le rapport doit expliquer comment les deux secrets sont mélangés et ce que la
construction garantit si l'une des deux familles devient vulnérable.

### 2.4 Mesures

La messagerie doit viser une consommation raisonnable. Il faut mesurer :

- les octets échangés par établissement de session ;
- les octets échangés par message ;
- le temps de calcul ;
- l'énergie si un banc fiable est disponible ;
- le coût par rapport à une version classique du même protocole.

Une mesure isolée ne suffit pas : répétitions, distributions et interprétation
sont obligatoires.

---

## 3. Problématique recommandée

### 3.1 Formulation principale

> Quel est le coût réel de l'ajout de ML-KEM à une messagerie asynchrone fondée
> sur X25519 lorsqu'elle fonctionne sur Android au-dessus de Bluetooth Low
> Energy, et quelles propriétés de sécurité PQXDH apporte-t-il face à des
> attaquants classiques et quantiques ?

Cette problématique relie directement :

- le protocole PQXDH ;
- la demande d'hybridation ;
- la messagerie concrète ;
- le transport contraint BLE ;
- la comparaison classique/hybride ;
- les mesures de bande passante, latence et énergie.

### 3.2 Questions de recherche secondaires

1. Quel surcoût ML-KEM-1024 impose-t-il sur la taille du handshake ?
2. Combien de fragments BLE supplémentaires ce surcoût produit-il ?
3. Quelle part de la latence vient des calculs cryptographiques et quelle part
   vient du transport ?
4. Le surcoût est-il payé seulement à l'ouverture de session ou également sur
   chaque message applicatif ?
5. Quel est le compromis entre ML-KEM-768 et ML-KEM-1024 si les deux profils
   sont étudiés ?
6. Quelles attaques actives sont effectivement détectées par l'application ?
7. Quels événements réseau ordinaires produisent les mêmes symptômes qu'une
   attaque ?
8. Une communication multi-hop change-t-elle la sécurité de bout en bout ou
   seulement la disponibilité et les métadonnées ?

### 3.3 Hypothèses expérimentales possibles

- H1 : PQXDH augmente fortement le volume du premier échange, mais presque pas
  celui des messages suivants.
- H2 : sur BLE, la fragmentation et les acquittements dominent le surcoût de
  latence davantage que le calcul ML-KEM sur un téléphone moderne.
- H3 : la cryptographie de bout en bout reste valide à travers un relais
  malveillant, tant que les identités sont authentifiées et les primitives
  restent sûres.
- H4 : l'application peut détecter les altérations et rejeux mais pas une copie
  passive des paquets.

Ces hypothèses doivent être confirmées ou réfutées par les résultats, pas
présentées comme des conclusions préalables.

---

## 4. Périmètre fonctionnel recommandé

### 4.1 Produit minimal obligatoire

Une application Android installable sur deux téléphones, capable de :

- créer et conserver une identité locale ;
- découvrir un pair proche en BLE ;
- échanger ou publier un paquet de préclés ;
- afficher une empreinte d'identité ou un QR code ;
- épingler l'identité d'un correspondant ;
- établir une session en mode classique X3DH ;
- établir une session en mode hybride PQXDH ;
- envoyer et recevoir plusieurs messages chiffrés ;
- refuser un message altéré ;
- refuser un rejeu ;
- signaler un changement de clé d'identité ;
- afficher des alertes compréhensibles ;
- produire des journaux de mesures sans exposer de secrets.

### 4.2 Progression réseau recommandée

Ordre de réalisation :

1. transport en mémoire pour les tests déterministes ;
2. transport local de développement, si utile ;
3. BLE direct entre deux téléphones ;
4. relais store-and-forward optionnel ;
5. mesh multi-hop uniquement comme extension.

Le mesh multi-hop est intéressant mais n'est pas requis pour répondre au sujet.
Il ajoute découverte, routage, duplication, expiration, boucles, fragmentation,
reconnexion et risques de déni de service. Il ne doit pas retarder la version
directe mesurable.

### 4.3 Hors périmètre conseillé

- compatibilité binaire avec Signal Messenger ;
- remplacement de libsignal ;
- groupes ;
- multiappareil ;
- appels audio ou vidéo ;
- découverte privée de contacts ;
- anonymat réseau ;
- dissimulation de la taille et du rythme des messages ;
- sauvegarde distante des clés ;
- résistance à un téléphone totalement compromis ;
- certification de sécurité ;
- usage avec de véritables secrets ;
- authentification résistante à un attaquant quantique actif ;
- Double Ratchet complet, sauf si le temps disponible le permet.

### 4.4 Livrable bonus raisonnable

Un mode relais dans lequel un troisième téléphone transporte des enveloppes
opaques entre Alice et Bob. Le relais peut stocker, copier, supprimer, retarder,
réordonner et modifier les paquets mais ne doit pas pouvoir lire le plaintext ni
modifier un message sans détection.

---

## 5. État actuel du dépôt

### 5.1 Dépôt et historique pertinent

- Dépôt de développement : `https://github.com/Aur3ns/PQXDH`.
- Branche principale : `main`.
- Commit de refonte PQXDH rev3 : `8c34714`.
- Commit de mise à jour du README principal : `2878dfb`.
- Licence du projet : MIT.

Toujours vérifier ces informations avec Git : ce document peut devenir ancien.

### 5.2 Nature du code existant

Le dépôt contient une bibliothèque C expérimentale qui implémente un profil
concret de PQXDH révision 3. Elle n'est pas encore une application de
messagerie.

Profil actuel :

| Fonction | Choix |
| --- | --- |
| Protocole initial | PQXDH révision 3 |
| Courbe | Curve25519/X25519 |
| Signature d'identité | XEd25519 randomisé |
| KEM postquantique | ML-KEM-1024 |
| KDF | HKDF-SHA-256 |
| AEAD | AES-256-GCM |
| Identifiants de clés | SHA-256 |
| Nonce AEAD | 96 bits aléatoires |
| Clé de session | 32 octets |

### 5.3 Dépendances

- `liboqs`, sous-module Git, pour ML-KEM-1024 ;
- `libxeddsa`, sous-module Git, pour XEd25519 ;
- libsodium pour X25519, aléa, comparaisons et effacement ;
- OpenSSL 3 pour HKDF, SHA-256 et AES-256-GCM ;
- CMake pour la construction principale ;
- vcpkg pour les dépendances Windows.

Les primitives ne sont pas recodées par le projet. La couche développée compose
les primitives, définit les structures, encode les messages et gère l'état.

### 5.4 Fonctions publiques principales

- `pqxdh_init` initialise les dépendances cryptographiques ;
- `pqxdh_generate_alice_keys` génère l'identité d'Alice ;
- `pqxdh_generate_pre_key_bundle` crée l'état public et privé de Bob ;
- `pqxdh_verify_pre_key_bundle` authentifie le bundle reçu ;
- `pqxdh_alice_create_initial_message` exécute le côté Alice ;
- `pqxdh_bob_process_initial_message` exécute le côté Bob ;
- `pqxdh_encode_initial_message` produit le format réseau ;
- `pqxdh_decode_initial_message` analyse ce format ;
- les fonctions `pqxdh_clear_*` effacent les objets sensibles ;
- `pqxdh_replay_check_and_mark` gère un cache de rejeu borné.

### 5.5 Tests existants

La suite actuelle comporte huit scénarios :

1. initialisation et unicité des clés ;
2. vérification du bundle et altération ;
3. accord Alice/Bob de bout en bout ;
4. encodage et décodage réseau ;
5. rejet d'un rejeu ;
6. intégrité AES-256-GCM ;
7. consommation des clés à usage unique ;
8. fonctionnement sans one-time prekey elliptique.

Ces tests ont passé localement avec :

- GNU Make ;
- CMake Release en Release ;
- bibliothèque statique ;
- bibliothèque partagée ;
- ASan et UBSan ;
- Debian Bookworm en conteneur ;
- Alpine 3.22 en conteneur ;
- un consommateur externe de la bibliothèque installée.

### 5.6 État de la CI

Au 7 septembre 2026 :

- Ubuntu GCC : succès ;
- Ubuntu Clang : succès ;
- Windows MSVC : échec à l'édition de liens.

Le job Windows compile les objets libxeddsa mais `pqxdh.lib` conserve des
références `__imp_*` non résolues vers les fonctions XEdDSA. La cause probable
est l'interaction entre les macros d'import/export Windows de libxeddsa et
l'intégration de ses object libraries dans la cible PQXDH. Ne pas annoncer que
Windows est supporté tant que ce job n'est pas vert et qu'un exécutable n'a pas
été testé sur Windows.

### 5.7 Limites actuelles

- aucune application Android ;
- aucun transport Bluetooth ;
- aucun client ni serveur ;
- aucun profil X3DH témoin ;
- aucun ratchet pour les messages suivants ;
- aucune base persistante des identités ;
- aucune interface d'empreinte ou QR code ;
- aucune alerte utilisateur ;
- replay tracker en mémoire, borné à 100 entrées ;
- aucune campagne de benchmarks reproductible ;
- aucune mesure d'énergie ;
- aucun rapport PDF ;
- aucun audit formalisé du code généré avec assistance ;
- aucune CI GitLab ;
- aucune conformité démontrée par des vecteurs officiels interopérables ;
- aucune revue de sécurité indépendante.

### 5.8 Signification exacte de « réimplémentation PQXDH »

Le transcript cryptographique suit PQXDH révision 3 avec un choix concret de
paramètres. La spécification laisse aux implémenteurs certains identifiants,
encodages, identifiants de clés, AEAD et format de conteneur.

Le projet n'est donc pas directement interopérable avec l'application Signal ou
avec tout format interne de libsignal. Il implémente le protocole de handshake,
pas toute la pile Signal.

---

## 6. Sources primaires à étudier

### 6.1 Sources obligatoires

1. NIST, FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism
   Standard* : <https://csrc.nist.gov/pubs/fips/203/final>
2. NIST, FIPS 204, *Module-Lattice-Based Digital Signature Standard* :
   <https://csrc.nist.gov/pubs/fips/204/final>
3. NIST, projet Post-Quantum Cryptography :
   <https://csrc.nist.gov/projects/post-quantum-cryptography>
4. ANSSI, *ANSSI views on the Post-Quantum Cryptography transition* :
   <https://cyber.gouv.fr/publications/anssi-views-post-quantum-cryptography-transition>
5. Signal, *The PQXDH Key Agreement Protocol*, révision 3 :
   <https://signal.org/docs/specifications/pqxdh/>
6. Signal, *The XEdDSA and VXEdDSA Signature Schemes* :
   <https://signal.org/docs/specifications/xeddsa/>
7. IETF, RFC 7748, *Elliptic Curves for Security* :
   <https://datatracker.ietf.org/doc/html/rfc7748>
8. IETF, RFC 5869, *HMAC-based Extract-and-Expand Key Derivation Function* :
   <https://datatracker.ietf.org/doc/html/rfc5869>
9. NIST, SP 800-38D, GCM :
   <https://csrc.nist.gov/pubs/sp/800/38/d/final>
10. NIST, FIPS 197, AES : <https://csrc.nist.gov/pubs/fips/197/final>

### 6.2 Bibliothèques et implémentations

- liboqs : <https://github.com/open-quantum-safe/liboqs>
- libxeddsa : <https://github.com/Syndace/libxeddsa>
- libsodium : <https://doc.libsodium.org/>
- OpenSSL : <https://docs.openssl.org/>
- PQClean : <https://github.com/PQClean/PQClean>

### 6.3 Sources complémentaires pertinentes

- analyse formelle PQXDH :
  <https://github.com/Inria-Prosecco/pqxdh-analysis>
- spécification X3DH : <https://signal.org/docs/specifications/x3dh/>
- Double Ratchet : <https://signal.org/docs/specifications/doubleratchet/>
- recommandations Android Keystore :
  <https://developer.android.com/privacy-and-security/keystore>
- documentation Android Bluetooth Low Energy :
  <https://developer.android.com/develop/connectivity/bluetooth/ble/overview>

### 6.4 Règles de citation

- Citer une source ne suffit pas : discuter ce qu'elle justifie.
- Associer chaque choix de primitive à une référence.
- Distinguer texte normatif, implémentation de référence et documentation
  secondaire.
- Noter la version et la date de consultation.
- Ne pas utiliser un billet de blog comme unique preuve d'une propriété.
- Vérifier l'existence d'errata du FIPS 203 au moment de rendre.
- Ne pas présenter un algorithme sélectionné pour standardisation comme déjà
  normalisé si son standard final n'existe pas encore.

---

## 7. État de l'art à couvrir dans le rapport

### 7.1 ML-KEM

ML-KEM est un KEM fondé sur Module-LWE, normalisé par FIPS 203. Il sert à
établir un secret partagé, pas à chiffrer directement une conversation.

Paramètres normalisés :

- ML-KEM-512 ;
- ML-KEM-768 ;
- ML-KEM-1024.

Le rapport doit comparer au minimum :

- niveau de sécurité revendiqué ;
- tailles clé publique, clé privée, ciphertext et secret partagé ;
- performances ;
- maturité des implémentations ;
- raisons du choix ML-KEM-1024 ;
- pertinence éventuelle de ML-KEM-768 sur Android/BLE.

### 7.2 ML-DSA

ML-DSA est une signature postquantique fondée sur les réseaux, normalisée par
FIPS 204. Elle doit être présentée dans l'état de l'art même si elle n'est pas
retenue pour PQXDH.

Expliquer pourquoi la réimplémentation stricte de PQXDH révision 3 conserve
XEdDSA : modifier la signature d'identité modifierait le protocole, les coûts et
ses propriétés de déniabilité. Ne pas affirmer que l'authentification actuelle
est postquantique.

### 7.3 SLH-DSA et autres familles

Présenter brièvement SLH-DSA, signature fondée sur le hachage normalisée par
FIPS 205, afin que l'état de l'art ne réduise pas la PQC à ML-KEM et ML-DSA.

Mentionner séparément les algorithmes encore en cours de normalisation, par
exemple HQC sélectionné comme KEM supplémentaire. Toujours vérifier leur statut
officiel à la date de rédaction.

### 7.4 Bibliothèques

Comparer les rôles :

- implémentation de référence : fidélité et validation d'un algorithme ;
- PQClean : code C portable et interfaces homogènes ;
- liboqs : expérimentation et intégration multi-algorithmes ;
- OpenSSL : intégration dans une bibliothèque généraliste ;
- libsodium : primitives classiques à API défensive ;
- libxeddsa : réalisation ciblée de XEd25519.

Documenter clairement que liboqs déconseille de protéger des données sensibles
en production avec cette bibliothèque de prototypage.

---

## 8. Modèle de menace

### 8.1 Actifs protégés

- contenu des messages ;
- clés de session ;
- clés d'identité privées ;
- clés de ratchet ;
- authenticité de l'identité d'un contact ;
- authenticité et ordre des messages ;
- état de consommation des préclés à usage unique.

Les métadonnées telles que présence, proximité, horaires, adresses Bluetooth,
volume et rythme ne sont pas entièrement protégées dans le périmètre proposé.

### 8.2 Attaquant réseau classique actif

Il peut :

- écouter toutes les transmissions ;
- copier les paquets ;
- supprimer des paquets ;
- retarder ou réordonner ;
- modifier ;
- injecter ;
- rejouer ;
- se comporter comme un périphérique BLE ;
- contrôler un relais ;
- contrôler le serveur de préclés si un serveur est ajouté.

Il ne peut pas, par hypothèse :

- extraire les secrets du téléphone ;
- casser X25519 ;
- forger XEd25519 ;
- casser ML-KEM ;
- casser HKDF ;
- forger un tag AES-GCM ;
- contourner une comparaison d'empreinte réellement authentifiée.

### 8.3 Attaquant passif avec ordinateur quantique futur

Il enregistre les échanges aujourd'hui. Plus tard, il sait résoudre le problème
classique protégeant X25519 mais ML-KEM reste sûr. La propriété recherchée est
la confidentialité des anciennes clés de session sous réserve de l'effacement
des secrets temporaires et des clés à usage unique pertinentes.

### 8.4 Attaquant quantique actif

Il agit pendant le protocole et peut casser l'authentification classique.
PQXDH révision 3 ne garantit pas l'authentification contre lui. Cette limite
doit apparaître dans l'interface pédagogique et dans le rapport.

### 8.5 Premier contact et TOFU

Si les utilisateurs acceptent automatiquement la première clé reçue, un MITM
présent au premier contact peut être épinglé comme identité légitime. Le mode
TOFU détecte les changements ultérieurs mais ne sécurise pas à lui seul le
premier échange.

La vérification d'une empreinte ou d'un QR code via un canal authentifié traite
ce problème sous l'hypothèse que ce canal n'est pas compromis.

### 8.6 Téléphone compromis

Un adversaire contrôlant totalement Android, lisant la mémoire du processus ou
utilisant l'application déverrouillée est hors périmètre. Android Keystore peut
réduire certains risques de stockage mais ne protège pas les secrets lorsqu'ils
sont utilisés par un processus compromis.

### 8.7 Déni de service

Un attaquant contrôlant le transport peut toujours empêcher la livraison. La
cryptographie ne garantit pas la disponibilité. Les gros objets ML-KEM peuvent
également amplifier les coûts de parsing, de stockage et de batterie ; borner
toutes les entrées est donc nécessaire.

---

## 9. Propriétés de sécurité explicites

### 9.1 Authentification des correspondants

Propriété proposée :

> Lorsqu'un utilisateur accepte une session associée à une clé d'identité
> préalablement vérifiée, aucun attaquant classique ne possédant pas la clé
> privée correspondante ne doit pouvoir être accepté comme ce correspondant,
> sauf rupture d'une primitive ou du canal de vérification.

Mécanismes nécessaires :

- signature XEd25519 des préclés de Bob ;
- contributions DH impliquant les identités ;
- AD liant les identités Alice et Bob ;
- empreinte ou QR code ;
- épinglage persistant ;
- alerte bloquante lors d'un changement inattendu.

### 9.2 Confidentialité classique

> Un attaquant réseau ne possédant pas les clés privées ne peut distinguer les
> contenus de deux messages de même longueur, en dehors des métadonnées exclues,
> sous les hypothèses de sécurité des primitives et d'unicité des nonces.

### 9.3 Protection harvest-now-decrypt-later

> Casser ultérieurement la composante X25519 d'un transcript enregistré ne doit
> pas suffire à reconstruire la clé initiale tant que ML-KEM demeure sûr et que
> les secrets nécessaires ont été effacés.

Ne pas appeler cette propriété « sécurité quantique totale ».

### 9.4 Intégrité et authenticité des messages

> Toute modification d'un ciphertext ou d'un champ d'en-tête authentifié doit
> provoquer le rejet, sauf probabilité négligeable de forge du tag.

### 9.5 Rejeu

> Une enveloppe déjà acceptée dans une session ne doit pas être livrée une
> seconde fois à l'application.

Utiliser `session_id` et `message_number`, pas seulement un cache borné global.

### 9.6 Ordre et suppression

> L'application doit détecter les numéros dupliqués et signaler les trous de
> séquence, sans affirmer qu'un trou prouve une attaque.

Un paquet perdu, une déconnexion et une suppression malveillante sont
indiscernables sans mécanisme supplémentaire.

### 9.7 Forward secrecy par message

Une chaîne symétrique qui efface `CK_i` après calcul de `CK_{i+1}` peut protéger
les anciens messages contre une compromission ultérieure de l'état courant.
Elle ne fournit pas à elle seule la récupération après compromission d'un
Double Ratchet complet.

### 9.8 Ce que signifie l'alerte d'« interception »

Une écoute purement passive est indétectable : copier des ondes ou des paquets
ne modifie aucune observation d'Alice ou Bob.

Alertes honnêtes à implémenter :

| Événement | Détection | Texte conseillé |
| --- | --- | --- |
| Tag AEAD invalide | Oui | Échec d'authentification : message rejeté |
| Rejeu | Oui, avec état persistant | Rejeu détecté : message rejeté |
| Identité épinglée modifiée | Oui | Clé d'identité modifiée : vérification requise |
| Préclé signée modifiée | Oui | Bundle de clés invalide |
| Trou de séquence | Oui | Message manquant ou retardé |
| Écoute passive | Non | Aucun message trompeur ne doit être affiché |
| Suppression du dernier message | Pas toujours | Indétectable sans accusé/timeout |

Ne jamais afficher « espion détecté » sur un simple échec réseau.

---

## 10. Description du profil PQXDH actuel

### 10.1 Encodages

- `EncodeEC(K)` : octet de type `0x05`, suivi de la coordonnée u X25519 de
  32 octets en little-endian ;
- `EncodeKEM(K)` : octet de type `0x0a`, suivi de la clé publique
  ML-KEM-1024 ;
- les domaines des encodages sont disjoints grâce aux octets de type.

### 10.2 Publication de Bob

Bob possède :

- `IK_B`, identité Curve25519 ;
- `SPK_B`, signed prekey X25519 ;
- `Sig(IK_B, EncodeEC(SPK_B), Z_SPK)` ;
- un éventuel `OPK_B`, one-time prekey X25519 ;
- `PQPK_B`, préclé ML-KEM-1024 à usage unique ou de dernier recours ;
- `Sig(IK_B, EncodeKEM(PQPK_B), Z_PQPK)` ;
- des identifiants SHA-256 pour sélectionner les clés privées correspondantes.

Chaque signature XEd25519 reçoit un `Z` aléatoire frais de 64 octets.

### 10.3 Calculs d'Alice

Après vérification du bundle et création de `EK_A` :

```text
DH1 = DH(IK_A, SPK_B)
DH2 = DH(EK_A, IK_B)
DH3 = DH(EK_A, SPK_B)
DH4 = DH(EK_A, OPK_B)   # seulement si OPK_B est présent
(CT, SS) = ML-KEM-ENC(PQPK_B)
```

### 10.4 Dérivation

```text
KM = DH1 || DH2 || DH3 [|| DH4] || SS
IKM = 0xff * 32 || KM
salt = 0x00 * 32
info = "PQXDH_CURVE25519_SHA-256_ML-KEM-1024"
SK = HKDF-SHA-256(IKM, salt, info, 32)
```

### 10.5 Données associées

```text
AD = EncodeEC(IK_A) || EncodeEC(IK_B)
```

ML-KEM lie la clé publique à son secret partagé ; le profil ne rajoute donc pas
`EncodeKEM(PQPK_B)` à l'AD.

### 10.6 Message initial

Le message contient notamment :

- version ;
- identité d'Alice ;
- clé éphémère d'Alice ;
- identifiants des préclés de Bob utilisées ;
- ciphertext ML-KEM ;
- nonce AES-GCM ;
- ciphertext initial et tag ;
- identifiant du message.

Le format est borné et non ambigu, mais spécifique à ce projet.

### 10.7 Traitement de Bob

Bob :

1. valide le bundle local ;
2. valide la structure du message ;
3. vérifie les identifiants de clés ;
4. refuse les clés one-time déjà consommées ;
5. recalcule DH1 à DH4 ;
6. décapsule `CT` ;
7. dérive `SK` ;
8. reconstruit `AD` ;
9. vérifie et déchiffre AES-GCM ;
10. marque le message comme reçu ;
11. efface les clés one-time consommées et les secrets temporaires.

---

## 11. Profil classique témoin

Le sujet impose une comparaison avec une version classique du même protocole.
Créer un profil X3DH aussi proche que possible du profil hybride.

### 11.1 Principes

- mêmes identités Curve25519 ;
- mêmes signatures XEd25519 ;
- mêmes DH1, DH2, DH3 et DH4 ;
- même AEAD ;
- même transport ;
- mêmes messages applicatifs ;
- même instrumentation ;
- aucune clé ni ciphertext ML-KEM ;
- KDF et `info` propres au profil X3DH, conformes à sa spécification.

### 11.2 Exigence de comparaison équitable

Ne pas comparer PQXDH sur téléphone à X3DH sur ordinateur. Ne pas inclure la
génération de clés dans une mesure d'un côté et l'exclure de l'autre. Les deux
profils doivent être exécutés dans le même binaire, sur le même appareil et
selon le même ordre expérimental.

### 11.3 API recommandée

Éviter un booléen dispersé `post_quantum=true`. Utiliser un profil explicite :

```c
typedef enum {
    SESSION_PROFILE_X3DH,
    SESSION_PROFILE_PQXDH
} SessionProfile;
```

Les formats réseau doivent porter un identifiant de version et de profil afin
d'empêcher les confusions et replis silencieux.

### 11.4 Downgrade

Si Alice demande PQXDH et que Bob ou un attaquant répond X3DH, l'application ne
doit pas accepter silencieusement. Le choix de profil doit être authentifié ou
épinglé dans l'état de la conversation.

---

## 12. Couche de messages après PQXDH

### 12.1 Pourquoi elle est nécessaire

PQXDH n'est qu'un handshake. Réutiliser directement `SK` avec des nonces
aléatoires pour toute la conversation ne constitue pas la meilleure
architecture et ne fournit pas la suppression progressive des anciennes clés.

### 12.2 Chaîne symétrique minimale

Pour rester dans un périmètre réaliste :

```text
RK = HKDF(SK, info="TP-PQXDH-root")
CK_send_0, CK_recv_0 = dérivés selon les rôles
MK_i = HMAC-SHA-256(CK_i, "message-key")
CK_i+1 = HMAC-SHA-256(CK_i, "chain-key")
```

Après dérivation et usage :

- effacer `MK_i` ;
- effacer `CK_i` ;
- conserver `CK_i+1` ;
- ne jamais réutiliser une paire clé/nonce ;
- borner le nombre de clés sautées pour les messages désordonnés.

Le choix final doit être décrit exactement et testé. Si une construction
standard existante est disponible, la préférer à une invention.

### 12.3 Enveloppe recommandée

```text
protocol_version
profile_id
session_id
sender_device_id
message_number
previous_chain_length (si utile)
nonce ou valeur servant à le dériver
ciphertext_length
ciphertext
authentication_tag
```

Authentifier tout l'en-tête stable comme AD.

### 12.4 Nonces

Option simple et auditable : dériver une clé unique `MK_i`, puis utiliser un
nonce fixé ou dérivé du numéro sous cette clé unique. Option alternative : nonce
aléatoire de 96 bits, avec analyse explicite du risque de collision. Ne jamais
combiner compteur réinitialisable et clé réutilisée.

### 12.5 Messages désordonnés

Décider et documenter :

- taille maximale de la fenêtre ;
- stockage des clés sautées ;
- expiration ;
- comportement au-delà de la fenêtre ;
- persistance atomique avant affichage ;
- protection contre un attaquant provoquant une allocation massive.

---

## 13. Architecture Android

### 13.1 Modules proposés

```text
android-app/
├── app/                         # UI et orchestration Android
├── crypto-api/                  # API Kotlin indépendante du transport
├── crypto-native/               # JNI + bibliothèque C via NDK
├── transport-api/               # abstraction de transport
├── transport-ble/               # implémentation BLE directe
├── storage/                     # Room/Keystore et transactions
├── benchmark/                   # instrumentation Android
└── attack-tools/                # relais et perturbations de test
```

### 13.2 Frontière JNI

Ne pas exposer directement les structures C brutes à Kotlin. Préférer une API
opaque :

- handles contrôlés ou buffers sérialisés ;
- tailles explicites ;
- codes d'erreur traduits en types Kotlin ;
- aucune clé dans les logs ;
- copies limitées ;
- effacement des buffers natifs ;
- tests de buffers nuls, tronqués ou surdimensionnés ;
- gestion correcte du cycle de vie Android.

### 13.3 Stockage

À conserver de manière transactionnelle :

- identité locale ;
- identités épinglées ;
- état de vérification des contacts ;
- signed prekeys actuelles et anciennes nécessaires ;
- one-time prekeys disponibles et consommées ;
- états des chaînes de messages ;
- compteurs ;
- identifiants de session ;
- statut de traitement des enveloppes.

Android Keystore ne stocke pas nécessairement tous les formats de clés du
protocole. Une solution possible est une clé de chiffrement protégée par
Keystore qui chiffre une base contenant les secrets. Ce choix doit être étudié,
testé et documenté, pas affirmé automatiquement sûr.

### 13.4 Identités et interface

L'écran d'un contact doit afficher :

- empreinte ;
- QR code ;
- état non vérifié/vérifié/modifié ;
- profil utilisé ;
- date de première observation ;
- date de dernière modification ;
- action explicite pour accepter une nouvelle identité.

Ne jamais remplacer automatiquement une identité vérifiée.

### 13.5 Journaux

Les logs peuvent contenir :

- codes d'étape ;
- tailles ;
- durées ;
- numéros d'expérience ;
- causes génériques d'échec ;
- versions des composants.

Ils ne doivent jamais contenir :

- clés privées ;
- shared secrets ;
- clés de session ;
- plaintext ;
- nonces secrets XEdDSA ;
- dumps complets de structures sensibles.

---

## 14. Transport Bluetooth Low Energy

### 14.1 Rôle du transport

BLE transporte des octets. Il ne remplace pas l'authentification de bout en
bout. Même si le lien Bluetooth possède sa propre sécurité, les garanties du TP
doivent venir du protocole applicatif.

### 14.2 Framing applicatif

Chaque objet logique doit être fragmenté :

```text
frame_version
transfer_id
object_type
fragment_index
fragment_count
total_length
payload_length
payload
```

Prévoir :

- longueur totale maximale avant allocation ;
- nombre maximal de fragments ;
- expiration des transferts incomplets ;
- déduplication ;
- acquittements ;
- retransmission ;
- CRC éventuel uniquement pour les erreurs accidentelles ;
- authentification cryptographique de l'objet reconstitué ;
- aucune confiance de sécurité dans le CRC.

### 14.3 États de connexion

Documenter une machine à états :

```text
IDLE
  -> DISCOVERING
  -> CONNECTING
  -> NEGOTIATING_TRANSPORT
  -> EXCHANGING_IDENTITY
  -> ESTABLISHING_SESSION
  -> READY
  -> DISCONNECTED / ERROR
```

Chaque transition doit avoir timeout, annulation et comportement de reprise.

### 14.4 Mesh et relais

Une enveloppe relayable doit contenir un identifiant opaque de destination, un
TTL, un identifiant de paquet et les fragments authentifiés. Un relais peut :

- copier ;
- stocker ;
- retarder ;
- supprimer ;
- réordonner ;
- modifier ;
- fabriquer du trafic.

Le chiffrement de bout en bout doit rendre lecture et modification silencieuse
impossibles sous les hypothèses annoncées. La suppression reste possible.

### 14.5 Métadonnées

Même chiffré, le système révèle potentiellement :

- proximité ;
- identifiants radio ;
- horaires ;
- volumes ;
- fréquence des échanges ;
- topologie approximative ;
- rôle de relais.

Ces fuites doivent être mentionnées dans le rapport.

---

## 15. Tests de sécurité applicatifs

Créer un harnais adversarial automatisé.

### 15.1 Matrice minimale

| Test | Action de l'attaquant | Résultat attendu |
| --- | --- | --- |
| Écoute | Copie sans modification | Aucune alerte, plaintext non exposé |
| Altération payload | Flip d'un bit | Rejet AEAD |
| Altération AD | Modification de l'identité/session | Rejet AEAD |
| Bundle falsifié | Modification SPK ou KEM | Signature refusée |
| Rejeu initial | Renvoi même handshake | Rejet ou comportement documenté |
| Rejeu message | Renvoi même compteur | Rejet |
| Réordonnancement | Inversion de deux messages | Fenêtre ou alerte conforme |
| Suppression | Retrait d'un numéro | Trou signalé, attaque non affirmée |
| Identité changée | Nouvelle clé pour contact connu | Blocage et alerte |
| MITM premier contact TOFU | Remplacement initial | Non détecté sans vérification externe |
| Downgrade | PQXDH remplacé par X3DH | Rejet si PQXDH exigé |
| Troncature | Fragment ou longueur manquante | Rejet sans crash |
| Surdimensionnement | Longueur hostile | Rejet avant allocation excessive |
| Mauvais profil | Confusion de format | Rejet |

### 15.2 Tests natifs

- unitaires ;
- intégration Alice/Bob ;
- vecteurs locaux déterministes lorsque possible ;
- tests négatifs ;
- fuzzing du décodeur ;
- ASan ;
- UBSan ;
- analyse statique ;
- tests répétés Release ;
- tests de concurrence sur l'état mutable.

### 15.3 Tests Android

- tests JVM de la logique non Android ;
- tests instrumentés JNI ;
- tests sur deux appareils réels ;
- reconnexion ;
- rotation d'écran et arrêt du processus ;
- persistance après redémarrage ;
- permissions Bluetooth refusées puis accordées ;
- changement de clé ;
- reprise d'un transfert fragmenté ;
- messages simultanés.

---

## 16. Protocole expérimental

### 16.1 Configurations principales

Comparer au minimum :

```text
CLASSICAL = X3DH + X25519 + XEd25519 + HKDF-SHA-256 + AES-256-GCM
HYBRID    = PQXDH + X25519 + ML-KEM-1024 + XEd25519
            + HKDF-SHA-256 + AES-256-GCM
```

Option facultative : un profil ML-KEM-768, clairement séparé de la comparaison
principale.

### 16.2 Opérations chronométrées

- génération identité ;
- génération signed prekey ;
- génération one-time X25519 ;
- génération ML-KEM ;
- signature bundle ;
- vérification bundle ;
- encapsulation ML-KEM ;
- décapsulation ML-KEM ;
- création complète côté Alice ;
- traitement complet côté Bob ;
- encodage ;
- décodage ;
- chiffrement d'un message ;
- déchiffrement d'un message ;
- handshake BLE complet ;
- message BLE complet.

### 16.3 Tailles de payload

Suggestion initiale :

```text
0, 16, 64, 256, 1024 et 4096 octets
```

La bibliothèque actuelle borne le plaintext initial à 1024 octets. Soit lever
proprement cette limite dans une nouvelle API, soit mesurer seulement les
tailles supportées et justifier le choix. Ne pas modifier une limite sans tests
de dépassement.

### 16.4 Répétitions

Protocole initial à confirmer après une étude pilote :

- 1 000 itérations d'échauffement pour les primitives rapides ;
- 10 000 itérations pour les opérations courtes ;
- au moins 1 000 handshakes par profil et appareil ;
- au moins 5 campagnes indépendantes ;
- ordre alterné ou randomisé des profils ;
- même appareil, batterie et environnement autant que possible ;
- aucune autre application lourde ;
- température enregistrée si accessible ;
- exclusion ou analyse séparée du thermal throttling.

### 16.5 Mesures de temps

Conserver les observations individuelles. Calculer :

- nombre `n` ;
- minimum ;
- maximum ;
- moyenne ;
- médiane ;
- écart-type ;
- p5 ;
- p25 ;
- p75 ;
- p95 ;
- p99 ;
- intervalle de confiance si justifié.

Ne jamais conclure avec une unique moyenne.

### 16.6 Mesures réseau

Pour chaque profil :

- taille bundle public ;
- taille message initial ;
- octets applicatifs ;
- octets BLE réels si mesurables ;
- fragments ;
- retransmissions ;
- acquittements ;
- durée jusqu'à session prête ;
- durée jusqu'à message affiché ;
- taux d'échec ;
- effet de la taille négociée des paquets ;
- effet de la distance et des pertes contrôlées.

### 16.7 Mesures mémoire et taille

- `sizeof` des structures publiques ;
- taille des clés et ciphertexts ;
- taille de la bibliothèque statique ;
- taille de la bibliothèque partagée ;
- taille de l'APK ;
- mémoire maximale du processus ;
- allocations pendant un handshake ;
- mémoire nécessaire au réassemblage BLE.

### 16.8 Énergie

Seulement avec une méthode défendable :

- Android Battery Historian pour une observation globale ;
- compteurs matériels ou banc externe si disponibles ;
- répétitions assez longues pour dépasser le bruit ;
- appareil, batterie, luminosité, radios et température contrôlés ;
- soustraction ou comparaison avec un témoin.

Si aucun banc fiable n'est disponible, écrire explicitement qu'aucune mesure
d'énergie n'est fournie. Ne pas convertir naïvement un temps CPU en joules.

### 16.9 Environnement

Enregistrer :

```text
date UTC
commit Git
état dirty ou clean
modèle du téléphone
SoC et architecture
version Android
niveau API
version NDK
ABI
mode de build
compilateur et version
options de compilation
versions/commits liboqs et libxeddsa
versions OpenSSL et libsodium
profil cryptographique
état batterie
température disponible
transport et paramètres BLE
distance
présence d'obstacles
nombre d'itérations
```

---

## 17. Format des données

### 17.1 CSV brut proposé

```text
campaign_id,iteration,timestamp_utc,git_commit,device_id,device_model,
android_version,abi,build_type,profile,operation,payload_bytes,
application_bytes,transport_bytes,fragment_count,retransmission_count,
duration_ns,success,error_code,battery_level,temperature_c
```

Le vrai CSV doit avoir une ligne d'en-tête unique et des champs documentés.

### 17.2 Métadonnées JSON

Un fichier par campagne :

```json
{
  "schema_version": 1,
  "campaign_id": "example-only",
  "git_commit": "replace-at-runtime",
  "device": {
    "manufacturer": "record-at-runtime",
    "model": "record-at-runtime",
    "android": "record-at-runtime",
    "abi": "record-at-runtime"
  },
  "crypto": {
    "classical_profile": "X3DH-X25519",
    "hybrid_profile": "PQXDH-ML-KEM-1024",
    "aead": "AES-256-GCM",
    "kdf": "HKDF-SHA-256"
  },
  "method": {
    "warmup": 1000,
    "iterations": 10000
  }
}
```

Cet exemple ne doit jamais être confondu avec une vraie observation.

### 17.3 Statistiques versionnées

Conserver dans Git :

- `summary.csv` ;
- figures finales ;
- métadonnées ;
- README des données ;
- scripts ;
- éventuellement données brutes compressées si raisonnables.

Documenter les exclusions : erreurs, chauffe, interruptions, valeurs aberrantes.
Ne jamais supprimer arbitrairement des outliers uniquement parce qu'ils gênent
la conclusion.

---

## 18. Graphiques attendus

1. distribution du temps de handshake X3DH contre PQXDH ;
2. temps d'encapsulation et décapsulation ;
3. octets par établissement de session ;
4. nombre de fragments BLE ;
5. latence selon la taille du message ;
6. surcoût relatif en pourcentage ;
7. taux d'échec ou retransmission selon distance/perte ;
8. taille du code et mémoire ;
9. énergie si le banc est valable.

Chaque figure doit préciser :

- unité ;
- taille de l'échantillon ;
- dispersion ;
- appareil ;
- profil ;
- options de compilation ;
- signification ;
- limites.

Les tableaux de données ne remplacent pas l'interprétation.

---

## 19. Audit du code assisté par IA

### 19.1 Déclaration minimale honnête

À adapter et compléter :

> OpenAI Codex a été utilisé pour analyser le dépôt initial, restructurer la
> construction, intégrer libxeddsa, rapprocher le transcript de PQXDH révision
> 3, produire certains tests et documents, et assister la conception de la
> partie TP. Les auteurs ont relu le code cryptographique produit ou modifié,
> l'ont confronté aux sources normatives et ont exécuté des tests positifs,
> négatifs et instrumentés. Les primitives ML-KEM, X25519, XEd25519, HKDF et
> AES-GCM proviennent de bibliothèques établies et n'ont pas été réimplémentées.

Ne conserver cette phrase que si l'audit annoncé a réellement été fait.

### 19.2 Périmètre d'audit

Auditer en priorité :

- `pqxdh.h` ;
- `pqxdh.c` ;
- sérialisation ;
- appels JNI futurs ;
- dérivation des clés de messages ;
- persistance des compteurs et clés ;
- parsing BLE ;
- négociation de profil ;
- gestion des erreurs ;
- tests cryptographiques écrits par le projet.

Les dépendances sont étudiées par leur documentation, origine, version, licence
et garanties publiées ; il n'est pas prévu de réauditer intégralement liboqs ou
OpenSSL.

### 19.3 Table d'audit à remplir

| ID | Fichier/fonction | Source | Invariant | Relecture | Test | Résultat |
| --- | --- | --- | --- | --- | --- | --- |
| A01 | Génération identité | XEdDSA/RFC 7748 | Clé adaptée aux deux usages | À faire | À faire | À faire |
| A02 | Signature SPK | PQXDH §3.2 | Signe exactement EncodeEC(SPK) | À faire | Partiel | À faire |
| A03 | Signature PQPK | PQXDH §3.2 | Signe exactement EncodeKEM(PQPK) | À faire | Partiel | À faire |
| A04 | DH1–DH4 Alice | PQXDH §3.3 | Bon ordre et bonnes clés | À faire | Partiel | À faire |
| A05 | DH1–DH4 Bob | PQXDH §3.4 | Symétrique à Alice | À faire | Partiel | À faire |
| A06 | KDF | PQXDH §2.2 | F, KM, sel, info exacts | À faire | À renforcer | À faire |
| A07 | AD | PQXDH §3.3 | Identités encodées exactes | À faire | À renforcer | À faire |
| A08 | AES-GCM | SP 800-38D | Unicité clé/nonce et tag | À faire | Partiel | À faire |
| A09 | Parsing | Format projet | Bornes avant accès | À faire | Fuzz partiel | À faire |
| A10 | One-time keys | PQXDH §3.4 | Consommation atomique | À faire | Partiel | À faire |
| A11 | Effacement | PQXDH | Secrets temporaires effacés | À faire | Analyse requise | À faire |
| A12 | Rejeu | PQXDH §4.2 | Rejet persistant | À faire | Partiel | À faire |

### 19.4 Défaut déjà découvert

Lors de la refonte XEdDSA, une première version conservait comme identité privée
le scalaire dont le signe avait été normalisé pour XEdDSA. Une fonction de
dérivation le clampait ensuite à nouveau, pouvant produire une clé publique
incohérente avec la signature. Le test passait parfois en Debug mais échouait de
façon répétée en Release.

Correction :

- conserver la clé privée Curve25519 originale pour X25519 ;
- dériver la clé publique Curve25519 depuis cette clé ;
- produire un scalaire temporaire à signe forcé uniquement pour chaque
  signature XEd25519 ;
- effacer ce scalaire temporaire ;
- répéter la suite 100 fois en Release.

Cet incident doit être revérifié dans l'historique et constitue un bon exemple
de l'intérêt de l'audit, mais il ne remplace pas l'audit complet.

### 19.5 Questions ligne par ligne

Pour chaque bloc sensible :

- les pointeurs peuvent-ils être nuls ?
- la longueur peut-elle déborder ?
- la conversion `size_t` vers `int` ou `uint32_t` est-elle sûre ?
- la sortie est-elle initialisée en cas d'échec ?
- un secret reste-t-il sur la pile ?
- la fonction appelée est-elle la bonne variante ?
- son code de retour est-il vérifié ?
- l'ordre des champs correspond-il au standard ?
- une comparaison secrète est-elle en temps constant ?
- une branche dépend-elle d'un secret ?
- un message hostile peut-il provoquer une grosse allocation ?
- l'état est-il modifié avant authentification ?
- un crash peut-il faire réutiliser une one-time key ?
- l'erreur révélée crée-t-elle un oracle ?
- le comportement concurrent est-il défini ?

---

## 20. Plan du rapport PDF

### 20.1 Structure proposée

1. Résumé
2. Introduction
3. Problématique
4. Périmètre et exclusions
5. Modèle d'attaquant
6. État de l'art postquantique
7. Propriétés de sécurité
8. X3DH et PQXDH
9. Choix des primitives et hybridation
10. Architecture Android/BLE
11. Implémentation
12. Audit du code assisté par IA
13. Protocole expérimental
14. Résultats
15. Analyse
16. Menaces à la validité
17. Limites
18. Conclusion
19. Bibliographie
20. Annexes de reproductibilité

### 20.2 Introduction

Présenter le problème de harvest-now-decrypt-later, l'intérêt d'un protocole
hybride et la contrainte BLE. Terminer l'introduction par la problématique, les
contributions et les exclusions.

### 20.3 Résultats

Ne pas seulement dire « PQXDH est plus lent ». Quantifier :

- différence absolue ;
- ratio ;
- dispersion ;
- effet applicatif ;
- coût uniquement initial ou récurrent ;
- rôle du BLE ;
- limites de généralisation.

### 20.4 Conclusion

Répondre directement à la problématique. Un résultat négatif est acceptable si
la sensibilité de l'expérience est quantifiée.

### 20.5 Typographie

- produire le PDF depuis LaTeX ;
- utiliser `listings` ou `minted` pour le code ;
- copier le texte des terminaux, sans capture d'écran ;
- numéroter figures et tableaux ;
- référencer chaque figure dans le texte ;
- maintenir une bibliographie propre ;
- définir chaque acronyme à sa première occurrence.

---

## 21. Structure cible du dépôt

```text
PQXDH/
├── README.md
├── LICENSE
├── CMakeLists.txt
├── include/
│   └── pqxdh/
├── src/
│   ├── pqxdh/
│   ├── x3dh/
│   ├── session/
│   └── wire/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── attacks/
│   └── vectors/
├── fuzz/
├── android-app/
│   ├── app/
│   ├── crypto-native/
│   ├── transport-ble/
│   ├── storage/
│   └── benchmark/
├── benchmarks/
│   ├── native/
│   ├── android/
│   └── scripts/
├── analysis/
│   ├── requirements.txt
│   ├── summarize.py
│   └── plot.py
├── results/
│   ├── README.md
│   ├── metadata/
│   ├── raw/
│   ├── summary/
│   └── figures/
├── docs/
│   ├── PROTOCOL.md
│   ├── THREAT_MODEL.md
│   ├── SECURITY_PROPERTIES.md
│   ├── WIRE_FORMAT.md
│   ├── EXPERIMENT.md
│   ├── AI_USAGE.md
│   └── AI_AUDIT.md
├── report/
│   ├── main.tex
│   ├── bibliography.bib
│   ├── figures/
│   └── report.pdf
├── tp_projet/
│   └── README.md
├── Dockerfile
├── compose.yaml
└── .gitlab-ci.yml
```

Ne pas réorganiser tout le dépôt en une fois sans nécessité. Effectuer des
migrations petites, testées et faciles à relire.

---

## 22. Reproductibilité

### 22.1 Commande cible

Un correcteur devrait pouvoir faire :

```sh
git clone --recursive URL_DU_GITLAB
cd NOM_DU_DEPOT
docker compose build
docker compose run --rm tests
docker compose run --rm benchmarks
docker compose run --rm report
```

La compilation Android devra avoir une commande Gradle documentée.

### 22.2 Sudo

La procédure principale ne doit pas demander `sudo` à répétition. Installer les
dépendances dans l'image Docker. Les scripts existants Debian/Alpine restent
utiles pour le développement mais ne devraient pas être l'unique méthode de
reproduction.

### 22.3 Versions figées

- sous-modules sur commits précis ;
- image Docker avec version, idéalement digest ;
- dépendances Python verrouillées ;
- version NDK fixée ;
- version Gradle fixée ;
- version CMake minimale ;
- métadonnées runtime enregistrées.

### 22.4 Test machine vierge

Avant rendu :

1. nouvelle VM ou runner ;
2. clone récursif ;
3. aucune dépendance cachée du poste développeur ;
4. construction ;
5. tests ;
6. benchmark court ;
7. génération PDF ;
8. comparaison des résultats attendus.

---

## 23. Feuille de route

### Phase 0 — Stabiliser la base

- [ ] corriger le lien MSVC/libxeddsa ;
- [ ] rendre la CI entièrement verte ;
- [ ] ajouter une CI GitLab ;
- [ ] vérifier licences des dépendances ;
- [ ] créer des tests KDF/AD plus ciblés ;
- [ ] créer le squelette d'audit ;
- [ ] figer les choix de protocole dans un document de décision.

### Phase 1 — Témoin classique et instrumentation native

- [ ] implémenter X3DH ;
- [ ] partager le code commun sans confondre les profils ;
- [ ] empêcher les downgrades ;
- [ ] créer le wire format versionné ;
- [ ] mesurer les tailles automatiquement ;
- [ ] ajouter un benchmark natif ;
- [ ] exporter CSV et métadonnées JSON ;
- [ ] produire une première comparaison pilote.

### Phase 2 — Couche de session

- [ ] définir la chaîne symétrique ;
- [ ] faire relire la construction ;
- [ ] utiliser une clé par message ;
- [ ] ajouter compteurs et `session_id` ;
- [ ] gérer les messages désordonnés ;
- [ ] persister atomiquement l'état ;
- [ ] tester rejeu, crash et concurrence.

### Phase 3 — Application Android locale

- [ ] projet Gradle/NDK minimal ;
- [ ] wrapper JNI ;
- [ ] tests JNI ;
- [ ] stockage des identités ;
- [ ] écran de contacts ;
- [ ] empreinte et QR code ;
- [ ] historique local ;
- [ ] alertes de sécurité.

### Phase 4 — BLE direct

- [ ] abstraction transport ;
- [ ] découverte ;
- [ ] connexion ;
- [ ] framing ;
- [ ] fragmentation/réassemblage ;
- [ ] timeouts et retransmissions ;
- [ ] deux téléphones réels ;
- [ ] tests adversariaux ;
- [ ] instrumentation réseau.

### Phase 5 — Campagne

- [ ] protocole pilote ;
- [ ] choisir `n` selon dispersion ;
- [ ] enregistrer environnement ;
- [ ] exécuter X3DH et PQXDH ;
- [ ] répéter sur plusieurs campagnes ;
- [ ] conserver les erreurs ;
- [ ] produire statistiques ;
- [ ] produire graphiques ;
- [ ] interpréter ;
- [ ] documenter menaces à la validité.

### Phase 6 — Mesh optionnel

- [ ] enveloppe relayable ;
- [ ] TTL ;
- [ ] déduplication ;
- [ ] troisième téléphone ;
- [ ] relais malveillant ;
- [ ] mesure multi-hop ;
- [ ] analyse des métadonnées.

### Phase 7 — Audit et rapport

- [ ] audit ligne par ligne ;
- [ ] matrice source/code/test ;
- [ ] déclaration IA ;
- [ ] rapport LaTeX ;
- [ ] bibliographie ;
- [ ] PDF ;
- [ ] clone vierge ;
- [ ] dépôt propre ;
- [ ] push GitLab avant échéance.

---

## 24. Critères d'acceptation du projet final

### 24.1 Cryptographie

- le rapport nomme exactement les versions implémentées ;
- le code correspond au rapport ;
- X3DH et PQXDH sont distinguables sans ambiguïté ;
- aucun repli silencieux ;
- aucune primitive recodée ;
- une clé distincte est utilisée par message ;
- les nonces ne sont pas réutilisés ;
- les identités sont vérifiables ;
- les one-time keys sont consommées atomiquement ;
- les secrets temporaires sont effacés au mieux des API disponibles.

### 24.2 Application

- deux téléphones peuvent échanger plusieurs messages ;
- les messages ne sont jamais affichés avant authentification ;
- les erreurs d'intégrité sont visibles ;
- les rejeux sont refusés ;
- les changements d'identité sont bloquants ;
- les pertes sont décrites honnêtement ;
- une écoute passive n'est pas annoncée comme détectée.

### 24.3 Expérience

- comparaison classique/hybride ;
- plusieurs répétitions ;
- résultats bruts ou reconstructibles ;
- distributions ;
- métadonnées ;
- scripts ;
- figures ;
- interprétation ;
- limites ;
- aucune mesure inventée.

### 24.4 Rendu

- rapport PDF présent ;
- code documenté ;
- statistiques présentes ;
- GitLab de l'école ;
- branche par défaut correcte ;
- clone récursif fonctionnel ;
- commande machine vierge testée ;
- déclaration IA ;
- audit présent ;
- aucun secret ni gros artefact inutile dans Git.

---

## 25. Risques de projet

| Risque | Impact | Réduction |
| --- | --- | --- |
| Mesh trop ambitieux | Messagerie de base inachevée | BLE direct d'abord |
| Pas de témoin X3DH | Partie 5.4 incomplète | Implémenter tôt |
| Mesures tardives | Pas de temps pour interpréter | Prototype benchmark tôt |
| Code IA incompris | Perte forte ou fraude | Audit continu |
| Confusion PQXDH/Signal | Rigueur invalidée | Vocabulaire précis |
| Windows rouge | Portabilité non démontrée | Corriger ou exclure honnêtement |
| TOFU présenté comme sûr | Modèle faux | Montrer attaque premier contact |
| Écoute dite détectable | Affirmation impossible | Distinguer passif/actif |
| Nonce réutilisé après crash | Confidentialité compromise | État transactionnel/clé unique |
| Benchmark non contrôlé | Résultats inutilisables | Métadonnées et répétitions |
| Chauffe Android | Biais temporel | Mesurer température, randomiser |
| Sous-modules inaccessibles | Clone impossible | Tester GitLab vierge |
| Données trop grosses | Dépôt inutilisable | Résumés et reconstruction |

---

## 26. Décisions prises

### D01 — PQXDH révision 3

Le projet cible la dernière révision publiée de PQXDH, pas une version
historique et pas un protocole seulement « inspiré ».

### D02 — ML-KEM-1024

Le profil courant utilise l'algorithme normalisé ML-KEM-1024 fourni par liboqs.
Ce choix doit être comparé à son coût sur BLE.

### D03 — Bibliothèque C conservée

Le cœur doit rester utilisable comme bibliothèque autonome. Android l'appelle
via le NDK/JNI ; la logique ne doit pas être dupliquée en Kotlin.

### D04 — Android/BLE

La démonstration cible deux téléphones Android proches. BLE direct est le MVP.
Le mesh multi-hop est un bonus.

### D05 — Témoin X3DH

La comparaison classique utilise X3DH avec la même pile symétrique et le même
transport.

### D06 — Alertes honnêtes

Détecter altération, rejeu, trou de séquence et changement d'identité. Ne pas
prétendre détecter une écoute passive.

### D07 — Pas de primitive maison

Toutes les primitives proviennent de bibliothèques établies. Le travail porte
sur le protocole et l'application.

### D08 — Usage IA déclaré

Codex a déjà contribué substantiellement. L'audit est une partie centrale du
livrable.

---

## 27. Questions encore ouvertes

- ML-KEM-1024 uniquement ou comparaison secondaire ML-KEM-768 ?
- deux appareils Android précis disponibles ?
- accès à un banc d'énergie ?
- BLE GATT classique, L2CAP CoC, ou autre abstraction ?
- besoin réel d'un serveur asynchrone en plus du BLE ?
- chaîne symétrique simple ou Double Ratchet ?
- politique exacte des messages désordonnés ?
- format des empreintes et QR codes ?
- langue de l'application ?
- binôme ou travail individuel ?
- format LaTeX imposé par l'école ?
- volume maximal accepté sur le GitLab ?
- environnement du correcteur et disponibilité de Docker ?

Ces questions ne bloquent pas la stabilisation, X3DH, le benchmark natif ou le
squelette documentaire.

---

## 28. Instructions prêtes à donner à un nouvel assistant

Copier et adapter ce prompt :

```text
Va sur le dépôt PQXDH et travaille depuis sa racine.

Lis intégralement tp_projet/README.md avant toute action. Lis ensuite README.md,
docs/PROTOCOL.md, SECURITY.md, pqxdh.h, pqxdh.c, test_pqxdh.c et CMakeLists.txt.
Inspecte l'état Git et les sous-modules. Ne supprime ni n'écrase les changements
existants.

Le but final est le sujet 5 du TP 2026 de cryptographie appliquée : produire une
messagerie Android sur Bluetooth Low Energy comparant un témoin X3DH classique
à PQXDH révision 3 avec X25519 + ML-KEM-1024. Le cœur C doit rester une
bibliothèque. BLE direct entre deux appareils est obligatoire avant tout mesh.

Les propriétés doivent être formulées sous un modèle d'attaquant explicite.
L'application doit détecter les altérations, rejeux et changements d'identité.
Elle ne doit jamais prétendre détecter une écoute passive. Aucun downgrade
silencieux n'est permis.

Ne recode aucune primitive. Utilise les bibliothèques établies. Confronte toute
modification cryptographique aux sources primaires. Ajoute tests positifs,
négatifs et documentation d'audit. Ne revendique ni audit indépendant, ni
compatibilité Signal, ni support de plateforme sans preuve.

Le dépôt doit finalement contenir le code, un rapport PDF, les scripts de
mesure, les métadonnées, les statistiques, les graphiques, une déclaration de
l'usage de Codex et un audit traçable du code généré.

Commence par vérifier l'état réel par rapport à la feuille de route de
tp_projet/README.md. Propose ou exécute la plus petite étape cohérente qui fait
avancer un critère du barème. Après chaque étape, lance les validations adaptées,
actualise la documentation et indique exactement ce qui reste non vérifié.
```

### 28.1 Informations critiques à rappeler à l'assistant

- ne pas transformer le projet en clone complet de Signal ;
- ne pas commencer par le mesh ;
- ne pas inventer de protocole cryptographique si une construction standard
  suffit ;
- ne pas confondre tests fonctionnels et preuve de sécurité ;
- ne pas inventer de chiffres de benchmark ;
- ne pas publier de clés ou plaintexts ;
- ne pas masquer l'échec Windows actuel ;
- ne pas pousser sur un dépôt externe sans autorisation ;
- ne pas modifier le rapport pour annoncer une fonction avant qu'elle existe ;
- maintenir la correspondance code/rapport.

---

## 29. Checklist avant chaque commit sensible

- [ ] changement clairement relié à une exigence ;
- [ ] source primaire identifiée ;
- [ ] menace et propriété identifiées ;
- [ ] API et format versionnés si nécessaire ;
- [ ] chemins d'erreur vérifiés ;
- [ ] secrets non journalisés ;
- [ ] tests positifs ;
- [ ] tests négatifs ;
- [ ] build Debug ;
- [ ] build Release ;
- [ ] sanitizers ;
- [ ] diff propre ;
- [ ] audit mis à jour ;
- [ ] README/rapport cohérents ;
- [ ] aucun chiffre non reproductible ;
- [ ] aucun artefact compilé ajouté ;
- [ ] message de commit descriptif.

---

## 30. Définition de « terminé »

Le projet n'est terminé que si une personne extérieure peut :

1. cloner le dépôt GitLab récursivement ;
2. construire sans assistance privée ;
3. lancer les tests ;
4. installer l'application sur les appareils documentés ;
5. établir une session X3DH ;
6. établir une session PQXDH ;
7. échanger plusieurs messages ;
8. reproduire les alertes de sécurité ;
9. relancer un benchmark court ;
10. reconstruire les statistiques et figures ;
11. lire le PDF ;
12. relier chaque affirmation importante à une source ou une mesure ;
13. consulter la déclaration IA et l'audit ;
14. comprendre les limites sans devoir contacter les auteurs.

Tant qu'un de ces points essentiels manque, le document doit le signaler comme
travail restant plutôt que comme fonctionnalité accomplie.
