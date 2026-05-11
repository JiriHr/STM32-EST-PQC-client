# Rychlý návod k nastavení

## Testování s STM

Pro nastavení prostředí pro testování s STM nejprve spusťte vývojový server Lamassu monolithic:

```bash
cd .../lamassuiot
go run monolithic/cmd/development/main.go
```

Počkejte, dokud se nezobrazí následující zpráva:

```text
Ready to PKI
```

Poté otevřete druhý terminál a spusťte nastavovací skript:

```bash
cd .../lamassuiot/PQCscripts
./setup_stm.sh
```

Skript vás vyzve k:

1. výběru verze ML-DSA,
2. potvrzení výchozí base URL nebo zadání vlastní.

Ve výchozím nastavení je skript připraven pro:

```text
http://127.0.0.1:8080
```

Base URL musí odpovídat konfiguraci Lamassu. Pokud používáte výchozí konfiguraci, nejsou nutné žádné změny.

Port lze změnit z `8080` na `8443` bez nutnosti měnit konfiguraci Lamassu.

> **Poznámka:**  
> TLS konfigurace se nachází v ´´´bash lamassuiot/backend/pkg/routes/utils.go ´´´, řádek 140~ Je zde pevně nastaveno hybridní zabezpečení. Pro zařízení bez TLS1.3 zakomentujte MinVersion a CurvePreferences a odkomentujte MaxVersion. Tím nastavíte endpoint na defaultní hodnoty z LamassuIoT.

---

## Samostatné testování

Samostatné testování je určeno pouze pro testování s Lamassu, bez STM.

Podle požadované varianty ML-DSA spusťte jeden z následujících příkazů z adresáře `lamassuiot`.

### ML-DSA-87

```bash
cd .../lamassuiot
go run ./monolithic/cmd/generate-est-mldsa87
```

### ML-DSA-65

```bash
cd .../lamassuiot
go run ./monolithic/cmd/generate-est-mldsa65
```

### ML-DSA-44

```bash
cd .../lamassuiot
go run ./monolithic/cmd/generate-est-mldsa44
```

Výsledný certifikát bude uložen jako:

```text
/tmp/lamassu-est-<ML-DSA-Variant>-cert.pem
```

Pro jednodušší použití je možné otevřít vygenerovaný certifikát přímo z výstupu v terminálu.

> **Poznámka:**  
> Konfigurace pro samostatné testování se po vypsání certifikátu ukončí. Nelze ji použít pro testování s STM.
