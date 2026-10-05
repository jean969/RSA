# RSA File Secure

Chiffrement et déchiffrement de fichiers par RSA, pour un exercice en binôme.
Python + Flask pour le serveur, HTML/CSS/JavaScript pour l'interface.

## Lancer

```bash
python -m venv .venv && source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
pytest                   # lance les tests
```

## Utilisation (scénario du binôme)

1. **Jean** ouvre « Clés », génère sa paire, télécharge `cle_publique.json` et `cle_privee.json`.
2. Jean envoie `cle_publique.json` à son binôme (la clé privée ne quitte jamais sa machine).
3. Le **binôme** ouvre « Chiffrer », choisit le fichier, importe `cle_publique.json`, télécharge le `.rsa`.
4. Jean ouvre « Déchiffrer », choisit le `.rsa`, importe `cle_privee.json`, récupère le fichier d'origine.

## Structure

```
app.py            routes Flask (aucun calcul)
rsa_core/         logique RSA, sans Flask
  primes.py       Miller-Rabin, génération de premiers
  keys.py         clés, génération, import/export JSON
  cipher.py       chiffrement par blocs, déchiffrement (CRT)
  fileformat.py   format du fichier .rsa
templates/        base, macros, 3 pages
static/           CSS, JS
tests/            pytest (dont p=61, q=53, e=17, M=65)
```

## Choix techniques

- **Blocs** : un bloc clair fait `(bits(n) - 1) // 8` octets, donc toujours < n (127 octets pour 1024 bits).
  Un bloc chiffré fait `ceil(bits(n) / 8)` octets (128), taille fixe : le déchiffrement sait où chaque bloc commence.
- **Dernier bloc et octets 0x00** : la taille d'origine est stockée dans l'en-tête, chaque bloc est reconstruit
  à longueur fixe, les zéros de tête sont donc conservés.
- **Format `.rsa`** : `RSAF | version | nom | taille | taille des blocs | SHA-256 | blocs chiffrés`.
  Le SHA-256 détecte une mauvaise clé ou un fichier corrompu.
- **Clé privée** : le fichier JSON contient aussi p et q (déchiffrement ~3x plus rapide, théorème des restes chinois).
  Il reste secret. Avec n et d saisis à la main, le calcul est plus lent mais correct.
- Le serveur ne stocke ni fichier ni clé.

## Limites (à citer dans le rapport)

- Le RSA « manuel » n'est pas sûr en pratique : il manque un padding (OAEP). Deux fichiers identiques
  donnent le même chiffré.
- On ne chiffre pas un fichier entier avec RSA en pratique : on chiffre une clé AES, et AES chiffre le fichier
  (schéma hybride). Ici l'énoncé impose RSA direct.
- 1024 bits est choisi pour la rapidité en Python ; 2048 bits est le minimum recommandé aujourd'hui.
- Pas d'authentification de la clé publique : un attaquant qui remplace la clé en route (homme du milieu) lirait les fichiers.
- Taille limitée à 8 Mo par fichier.
- Vitesse : le déchiffrement RSA est coûteux. Mesuré (1024 bits, machine de test) : chiffrement ~0,5 s/Mo,
  déchiffrement ~14 s/Mo avec le fichier de clé privée complet, environ 2x plus lent avec n et d saisis à la main.
  Un fichier de 2,4 Mo prend donc de l'ordre de 30 s à déchiffrer : la page affiche « en cours » pendant ce temps.
  C'est une raison de plus d'utiliser le schéma hybride avec AES en pratique.

## Améliorations possibles

Boîte de réception par compte, lien de partage temporaire, schéma hybride RSA-OAEP + AES-GCM, empreinte de clé
pour vérifier la clé du binôme.
