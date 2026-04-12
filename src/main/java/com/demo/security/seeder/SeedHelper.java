package com.demo.security.seeder;

/**
 * Gedeelde testdata voor alle POC-seeders.
 * 100 unieke namen × 100 unieke notities = 10.000 combinaties.
 * Elke waarde komt ~100× voor — realistisch voor zoekresultaten.
 */
public final class SeedHelper {

    public static final int TOTAAL        = 10_000;
    public static final int BATCH         = 500;
    public static final int UNIEKE_WAARDEN = 100;

    private static final String[] VOORNAMEN = {
        "Emma", "Noah", "Olivia", "Liam", "Ava", "Elijah", "Sophia", "James",
        "Isabella", "Oliver", "Mia", "Benjamin", "Charlotte", "Lucas", "Amelia",
        "Mason", "Harper", "Ethan", "Evelyn", "Alexander"
    };

    private static final String[] ACHTERNAMEN = {
        "de Vries", "van den Berg", "Jansen", "Bakker", "Visser",
        "Smit", "Meijer", "de Boer", "Mulder", "van der Linden",
        "de Groot", "Bos", "Vos", "Peters", "Hendriks",
        "van Leeuwen", "Dekker", "Brouwer", "de Wit", "Dijkstra"
    };

    private static final String[] NOTITIE_TEMPLATES = {
        "Vertrouwelijk dossier nummer %d",
        "Medische notitie %d",
        "Financieel rapport Q%d",
        "Interne memo %d",
        "Beveiligingsincident %d",
        "Klachtdossier %d",
        "Contractnummer %d",
        "Projectcode %d",
        "Casusnummer %d",
        "Referentiedocument %d"
    };

    private SeedHelper() {}

    public static String naam(int index) {
        int i = index % UNIEKE_WAARDEN;
        return VOORNAMEN[i % VOORNAMEN.length] + " " + ACHTERNAMEN[i % ACHTERNAMEN.length];
    }

    public static String notitie(int index) {
        int i = index % UNIEKE_WAARDEN;
        String template = NOTITIE_TEMPLATES[i % NOTITIE_TEMPLATES.length];
        return String.format(template, i + 1);
    }

    /** Enkelvoudige vertrouwelijke waarde voor POCs met één encrypted veld. */
    public static String vertrouwelijk(int index) {
        return naam(index);
    }
}
