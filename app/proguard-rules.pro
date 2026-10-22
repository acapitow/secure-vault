# --- MASVS-CODE / RESILIENCE : obfuscation R8 activée en release ---

# Supprime les appels de log non critiques du bytecode release
# (évite toute fuite accidentelle dans Logcat — MASVS-STORAGE-2).
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# Bouncy Castle : on n'utilise que les générateurs Argon2 en appel direct,
# R8 conserve donc ce qui est atteint. Les avertissements sur les classes
# JDK absentes d'Android sont sans objet.
-dontwarn org.bouncycastle.**

# Ne pas conserver les noms de fichiers sources / numéros de ligne en release.
-renamesourcefileattribute ""
