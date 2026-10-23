# Modèle de menace

## Ce qu'on protège

- les mots de passe, notes et secrets TOTP ;
- les métadonnées (titres, identifiants, sites), qui révèlent les comptes utilisés ;
- le mot de passe maître.

## Attaquants et réponses

| # | Attaquant | Capacités | Protections | Résultat attendu |
|---|---|---|---|---|
| A1 | Vol du téléphone **verrouillé** | accès physique, pas de code | chiffrement Android + coffre verrouillé (écran éteint = verrouillage immédiat) | aucun accès |
| A2 | Téléphone **déverrouillé** laissé sans surveillance | utilise l'interface | verrouillage auto (5 min / 15 s / écran éteint), mot de passe redemandé pour le changer, délai croissant après 5 échecs | accès seulement dans la fenêtre avant verrouillage |
| A3 | Extraction du fichier (sauvegarde, ADB, outil forensique) | copie de `vault.json` | `allowBackup=false`, règles d'extraction vides, `noBackupFilesDir` ; slot chiffré par une clé matérielle | **aucune attaque hors ligne possible**, même sur un mot de passe faible |
| A4 | Application malveillante sans privilèges | superposition, accessibilité, presse-papiers, captures | `filterTouchesWhenObscured`, `setHideOverlayWindows`, `FLAG_SECURE`, données sensibles pour l'accessibilité (API 34), autofill exclu, presse-papiers sensible effacé à 30 s, aucun composant propre exporté sauf le lanceur | pas de lecture d'écran ni de détournement de clics |
| A5 | Personne qui connaît le **code de l'appareil** | peut enrôler son empreinte | clé biométrique invalidée par tout nouvel enrôlement | la biométrie se désactive, mot de passe maître exigé |
| A6 | Analyste avec appareil **rooté** et outils (Frida, Xposed, débogueur) | lecture mémoire, hooks | détection débogueur / instrumentation / re-signature → ouverture refusée en release ; R8 | coût d'attaque élevé — **pas une garantie** (voir limites) |
| A7 | QR code piégé | contenu arbitraire | analyse stricte : schéma, type, paramètres dupliqués, émetteurs contradictoires, bornes, encodage, longueur | refus explicite, jamais de valeur par défaut silencieuse |

Hors périmètre : système compromis au niveau noyau ou firmware, attaques matérielles sur le TEE/StrongBox,
contrainte physique de l'utilisateur, clavier (IME) malveillant installé et choisi par l'utilisateur.

## Limites assumées

Ces points sont connus, documentés dans le code et acceptés :

1. **Copies en mémoire non effaçables.** Les secrets transitent en `CharArray`/`ByteArray` effacés après
   usage, mais :
   - un secret **affiché** passe par une `String` (exigée par `Text`) tant qu'il est visible ;
   - les champs de saisie Compose gardent un tampon interne qu'on peut vider, pas effacer ;
   - le fournisseur JCA garde une copie interne des clés (`SecretKeySpec`) ;
   - une URI `otpauth://` scannée arrive sous forme de `String`.

   Un attaquant capable de lire la mémoire du processus (A6) peut y trouver des secrets pendant que le
   coffre est ouvert. Le verrouillage les rend inaccessibles, sans garantir leur effacement immédiat.
2. **Les détections d'environnement sont contournables.** Toute vérification exécutée dans le processus
   peut être neutralisée par un attaquant qui contrôle l'appareil (Magisk DenyList, Frida renommé, patch
   de l'APK). Le root n'est volontairement qu'un avertissement : bloquer priverait un utilisateur
   légitime de ses données, et la protection réelle reste la cryptographie.
3. **Limitation des tentatives contournable avec root.** Le compteur est dans les SharedPreferences ;
   un attaquant root peut le remettre à zéro. Chaque essai coûte néanmoins une dérivation Argon2id
   (64 Mio) et ne peut se faire que sur l'appareil (clé matérielle).
4. **Effacement du presse-papiers retardé** si Android gèle l'application en arrière-plan. Android 13+
   vide de toute façon le presse-papiers après une heure.
5. **Pas de sauvegarde ni d'export.** Choix de conception (A3), au prix d'un risque de perte de données.
6. **`setUnlockedDeviceRequired` non utilisé** sur la clé appareil : sur certains appareils, retirer le
   verrouillage d'écran rendrait la clé, donc le coffre, définitivement inutilisable.
7. **Secrets TOTP de 80 bits acceptés** (minimum RFC 4226 : 128 bits), car encore courants chez les services.

## Pistes d'amélioration

- export chiffré (fichier protégé par une phrase de passe dédiée) ;
- analyse de composition logicielle automatisée en CI (Dependabot / OSV) ;
- tests instrumentés sur émulateur pour le Keystore et BiometricPrompt ;
- attestation de clé (Key Attestation) pour prouver que les clés sont réellement matérielles.
