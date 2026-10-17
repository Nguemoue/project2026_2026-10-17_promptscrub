# PromptScrub

Masque secrets, jetons et données perso **avant** de coller un log dans ChatGPT, Slack, une issue GitHub ou un prompt.

Scrub secrets and personal data out of a log **before** you paste it into a chat, a ticket, or a prompt.

Un seul fichier PHP, zéro dépendance. Rien n'est envoyé nulle part.

```text
contact ada@acme.io
DATABASE_URL=postgres://app:s3cr3t-value@db.internal:5432/app
APP_KEY=base64:dGhpcy1pcy1qdXN0LWEtZGVtby1rZXktdmFsdWU
MAIL_PASSWORD=changeme
card=4242 4242 4242 4242
```

devient :

```text
contact [REDACTED:email]
DATABASE_URL=postgres://app:[REDACTED:url_password]@db.internal:5432/app
APP_KEY=[REDACTED:env_secret]
MAIL_PASSWORD=changeme
card=[REDACTED:payment_card]
```

Le mot de passe d'exemple `changeme` est laissé tel quel. L'hôte de la base reste lisible. L'UUID aussi.

## Pourquoi

La plupart des fuites ne viennent pas d'un exploit. Elles viennent d'un copier-coller : un `.env`, une stack trace, une URL `postgres://user:motdepasse@…` collée dans un chat pour « juste débugger ».

PromptScrub est le réflexe d'avant le collage. Il tourne en local.

## Installation

PHP 8.1 ou plus récent. Rien d'autre.

```bash
curl -fsSL -o promptscrub.php https://raw.githubusercontent.com/Nguemoue/project2026_2026-10-17_promptscrub/main/promptscrub.php
php promptscrub.php --self-test
```

Le self-test fabrique des jetons factices en mémoire (AWS, GitHub, Stripe, Slack, clé PEM, JWT…) et vérifie qu'ils disparaissent du résultat, sans jamais les écrire dans le dépôt.

## Usage

```bash
php promptscrub.php app.log > app.clean.log
php promptscrub.php --check app.log          # code 2 si quelque chose a été masqué
git diff --cached | php promptscrub.php --check
php promptscrub.php --json dossier/src
php promptscrub.php --no-email incident.txt
```

Le texte masqué va sur **stdout**, le résumé sur **stderr**. Avec plusieurs fichiers, ou avec `--check`, seul le résumé est affiché : le corps n'est pas réimprimé.

Page locale, si tu préfères coller dans un formulaire :

```bash
php -S 127.0.0.1:8765 promptscrub.php
```

Le formulaire traite la requête en mémoire et ne l'écrit pas. Ne l'expose pas sur Internet : le texte passerait par la machine qui sert la page.

### CI

```yaml
- uses: shivammathur/setup-php@v2
  with:
    php-version: "8.3"
- run: php promptscrub.php --check .
```

`--check` sur un dossier ignore `vendor/`, `node_modules/`, `.git/` et les fichiers binaires.

## Ce qui est détecté

| Règle | Exemple de cas |
|---|---|
| `aws_access_key_id`, `aws_secret_access_key` | clé AWS, le secret seulement s'il est à côté de son nom |
| `github_token`, `gitlab_token`, `npm_token`, `pypi_token` | jetons de forge et de registres |
| `slack_token`, `slack_webhook`, `discord_webhook` | jetons et webhooks |
| `stripe_secret_key`, `openai_key`, `anthropic_key`, `xai_key`, `groq_key`, `google_api_key`, `sendgrid_key`, `shopify_token`, `huggingface_token` | clés d'API au format reconnu |
| `private_key` | bloc PEM |
| `jwt` | JWT dont l'en-tête déclare un `alg` |
| `bearer_token`, `basic_auth` | en-têtes Authorization |
| `url_password` | mot de passe dans une URL, hôte conservé |
| `env_secret` | valeur assignée à `APP_KEY`, `PASSWORD`, `TOKEN`, `API_KEY`… |
| `payment_card` | carte qui passe Luhn (groupée, ou à côté d'un mot-clé) |
| `iban` | IBAN avec pays, longueur et clé mod 97 |
| `email` | adresse, hors `example.com`, `.test`, `.invalid` |

Les placeholders ne sont pas masqués : `changeme`, `your_api_key`, `xxxx`, `${VAR}`, `<secret>`. Un mot de passe très court non plus, pour éviter le bruit dans la doc (`password: required`).

Liste à jour : `php promptscrub.php --rules`.

## Ce que ça ne fait pas

C'est une heuristique, pas un audit. Un secret sans forme reconnaissable peut passer. Un faux positif peut arriver. Relis le texte avant de l'envoyer. PromptScrub ne remplace pas un gestionnaire de secrets, ni la rotation d'une clé déjà publiée.

## English

PromptScrub is a single-file PHP 8.1+ tool. It rewrites logs so you can paste them into an AI chat or a ticket without shipping live credentials.

```bash
php promptscrub.php --check app.log
php promptscrub.php --self-test
```

Exit `0` when nothing was found (or when redacted text was printed). Exit `2` with `--check` when something was redacted. Exit `1` on usage errors. The report lists the rule and the line, never the secret itself.

## Licence

MIT. Copyright (c) 2026 Luc (Nguemoue).
