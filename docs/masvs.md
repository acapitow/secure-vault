# Correspondance OWASP MASVS v2

Profil visé : **L2** (applications manipulant des données sensibles) + **R** (résilience).
Chemins relatifs à `app/src/main/java/io/github/acapitow/vault/` ; tests dans `app/src/test/…`.

## MASVS-STORAGE

| Contrôle | Mise en œuvre | Code | Tests |
|---|---|---|---|
| **STORAGE-1** Stockage sécurisé des données sensibles | Coffre chiffré AES-256-GCM, DEK enveloppée par Argon2id **et** une clé Keystore non extractible ; chiffrement par champ | `vault/VaultRepository.kt`, `vault/DeviceKey.kt`, `vault/Vault.kt` | `VaultRepositoryTest` (aucun texte clair dans le fichier, clé appareil différente refusée), `VaultTest` |
| **STORAGE-2** Prévention des fuites | `allowBackup=false`, règles de sauvegarde et de transfert vides, `noBackupFilesDir` ; `FLAG_SECURE` ; presse-papiers sensible effacé ; secrets hors de l'état sauvegardé de l'activité ; `toString()` sans secret ; logs v/d/i retirés par R8 | `AndroidManifest.xml`, `res/xml/*`, `ui/SecureClipboard.kt`, `ui/Components.kt`, `totp/TotpAccount.kt`, `proguard-rules.pro` | `OtpAuthUriTest` (toString), `VaultTest` |

## MASVS-CRYPTO

| Contrôle | Mise en œuvre | Code | Tests |
|---|---|---|---|
| **CRYPTO-1** Cryptographie forte et correctement utilisée | AES-256-GCM (nonce généré par le fournisseur, version authentifiée, AAD de contexte), Argon2id, HMAC-SHA1/256/512 pour TOTP, `SecureRandom` uniquement, comparaisons en temps constant | `crypto/AesGcm.kt`, `crypto/Argon2id.kt`, `crypto/Secrets.kt`, `crypto/PasswordGenerator.kt`, `totp/Totp.kt` | vecteurs NIST GCM, RFC 9106, RFC 4226, RFC 6238 ; altération octet par octet ; `PasswordGeneratorTest` |
| **CRYPTO-2** Gestion des clés | Hiérarchie DEK / KEK / clé appareil / clé biométrique ; clés Keystore StrongBox ou TEE, IV imposé ; paramètres KDF bornés contre la dégradation ; effacement des clés intermédiaires | `vault/AndroidKeys.kt`, `vault/VaultFormat.kt`, `crypto/Argon2id.kt` | `Argon2idTest` (bornes), `VaultRepositoryTest` (altération de l'en-tête) |

## MASVS-AUTH

| Contrôle | Mise en œuvre | Code | Tests |
|---|---|---|---|
| **AUTH-1** Protocoles d'authentification | Sans objet : aucune authentification distante (application hors ligne) | — | — |
| **AUTH-2** Authentification locale | Mot de passe maître (≥ 12 caractères) ; BiometricPrompt **avec CryptoObject**, biométrie forte uniquement, clé invalidée à l'enrôlement ; délai croissant après 5 échecs ; verrouillage automatique | `ui/BiometricAuth.kt`, `vault/BiometricKey.kt`, `session/UnlockThrottle.kt`, `session/VaultSession.kt` | `BiometricRepositoryTest`, `UnlockThrottleTest`, `VaultSessionTest` |
| **AUTH-3** Opérations sensibles | Changement du mot de passe maître : ancien mot de passe redemandé même coffre ouvert ; activation biométrique confirmée par une authentification | `vault/VaultRepository.kt` (`changePassword`), `ui/SettingsScreen.kt` | `VaultRepositoryTest` (changement de mot de passe) |

## MASVS-NETWORK

| Contrôle | Mise en œuvre |
|---|---|
| **NETWORK-1 / 2** | Sans objet : permissions `INTERNET` et `ACCESS_NETWORK_STATE` retirées explicitement du manifeste fusionné ; `usesCleartextTraffic=false` en défense en profondeur |

## MASVS-PLATFORM

| Contrôle | Mise en œuvre | Code |
|---|---|---|
| **PLATFORM-1** IPC | Seul composant propre exporté : le lanceur. Composants ajoutés par les bibliothèques : `InitializationProvider` (androidx.startup) et `MetadataHolderService` (CameraX) non exportés ; `ProfileInstallReceiver` (androidx.profileinstaller) exporté mais réservé à la permission système `DUMP`. Récepteur `SCREEN_OFF` enregistré non exporté | `AndroidManifest.xml`, `VaultApp.kt` |
| **PLATFORM-2** WebViews | Sans objet : aucune WebView | — |
| **PLATFORM-3** Interface utilisateur | `FLAG_SECURE`, pas de capture dans les récents ; anti-tapjacking (`filterTouchesWhenObscured`, `setHideOverlayWindows`) ; accessibilité limitée aux vrais outils (API 34) ; autofill exclu ; champs de mot de passe sans copier/couper ni apprentissage clavier ; secrets masqués par défaut | `ui/MainActivity.kt`, `ui/Components.kt` |

## MASVS-CODE

| Contrôle | Mise en œuvre | Code / tests |
|---|---|---|
| **CODE-1** Plateforme à jour | minSdk 28, targetSdk 37 | `app/build.gradle.kts` |
| **CODE-2** Mises à jour | Sans objet (pas de serveur) ; mises à jour par APK signé avec la même clé, `versionCode` croissant | — |
| **CODE-3** Composants sans vulnérabilité connue | Versions récentes vérifiées et figées (catalogue), wrapper Gradle vérifié, dépôts restreints, actions CI épinglées par SHA. *Manque : analyse automatisée (voir [modèle de menace](threat-model.md))* | `gradle/libs.versions.toml`, `settings.gradle.kts`, `.github/workflows/build.yml` |
| **CODE-4** Entrées non fiables | URI `otpauth://` (QR code) : analyse stricte ; Base32 strict ; fichier du coffre : format, bornes, AAD ; longueurs bornées | `totp/OtpAuthUri.kt`, `totp/Base32.kt`, `vault/VaultRepository.kt` | `OtpAuthUriTest`, `Base32Test`, `VaultRepositoryTest` |

## MASVS-RESILIENCE

| Contrôle | Mise en œuvre | Code | Tests |
|---|---|---|---|
| **RESILIENCE-1** Intégrité de la plateforme | Détection root (binaires `su`, `test-keys`) et émulateur → avertissement | `security/IntegrityChecker.kt`, `security/AndroidProbe.kt` | `IntegrityCheckerTest` |
| **RESILIENCE-2** Anti-altération | Empreinte du certificat de signature vérifiée au lancement (valeur injectée au build, contrôlée par la CI) → ouverture refusée | `security/IntegrityChecker.kt`, `app/build.gradle.kts`, `.github/workflows/build.yml` | `IntegrityCheckerTest` |
| **RESILIENCE-3** Anti-analyse statique | R8 (minification, obfuscation, suppression des noms de fichiers sources) | `proguard-rules.pro` | — |
| **RESILIENCE-4** Anti-analyse dynamique | Débogueur (JDWP, `TracerPid`) et instrumentation (Frida, Xposed/LSPosed, Substrate) → ouverture refusée, la clé du coffre n'est jamais dérivée | `security/IntegrityChecker.kt`, `session/VaultSession.kt` | `IntegrityCheckerTest`, `VaultSessionTest` |

## MASVS-PRIVACY

| Contrôle | Mise en œuvre |
|---|---|
| **PRIVACY-1** Minimisation | Seule permission demandée à l'usage : la caméra, au moment du scan ; images analysées en mémoire, jamais enregistrées |
| **PRIVACY-2** Non-identification | Aucun identifiant, aucune télémétrie, aucun SDK tiers de suivi |
| **PRIVACY-3** Transparence | Écran d'explication avant la demande de caméra |
| **PRIVACY-4** Contrôle utilisateur | Biométrie activable / désactivable, refus de la caméra sans perte de fonctionnalité (saisie manuelle) |
