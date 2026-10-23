# Politique de sécurité

Secure Vault est un projet portfolio. Les signalements de vulnérabilités sont néanmoins bienvenus.

## Signaler une vulnérabilité

Merci de **ne pas ouvrir d'issue publique**. Utilise l'onglet **Security → Report a vulnerability**
du dépôt (signalement privé GitHub), avec :

- la version (`versionName`) et le commit ;
- le modèle d'appareil et la version d'Android ;
- les étapes de reproduction et l'impact estimé.

## Périmètre

Dans le périmètre : la branche `main`, le format du coffre, la cryptographie, le déverrouillage,
les fuites de données vers d'autres applications ou le système.

Hors périmètre : les limites documentées dans le [modèle de menace](docs/threat-model.md)
(copies en mémoire, contournement des détections par un attaquant root), et la branche `vulnerable`,
volontairement vulnérable à des fins pédagogiques.
