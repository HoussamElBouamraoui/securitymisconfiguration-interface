# 🔧 Fix Backend - Multi-User Support avec JWT

## ✅ Étape A : Décorateur `require_auth` - Exposition du User dans les Requests

### Changement
Dans le décorateur `@require_auth`, après la validation du token JWT:

```python
request.jwt_payload = payload
request.user_id = payload.get("user_id")
request.user_role = payload.get("role")
```

### Résultat
- ✅ **`request.user_id`** : ID de l'utilisateur connecté (disponible dans tous les endpoints protégés)
- ✅ **`request.user_role`** : Role de l'utilisateur ("user" ou "admin")
- ✅ **`request.jwt_payload`** : Payload JWT complet pour accès avancé

---

## ✅ Étape B : Endpoint `/scan` - Utilisation du User Réel

### Avant
```python
user_id = get_or_create_system_user_id()  # ❌ Tous les scans = user "system"
```

### Après
```python
user_id = request.user_id
if not user_id:
    return jsonify({"error": "Token invalide: user_id manquant"}), 401
```

### Résultat
- ✅ **Chaque scan est lié à l'utilisateur qui l'a lancé**
- ✅ Les logs d'audit tracent le vrai utilisateur
- ✅ Support multi-utilisateur complet

---

## ✅ Étape C : Endpoint `/auth/me` - Diagnostic

### Nouveau endpoint
```python
@app.get("/auth/me")
@require_auth
def me():
    return jsonify({
        "user_id": request.user_id,
        "role": request.user_role,
        "payload": request.jwt_payload,
    })
```

### Utilisation
Pour vérifier qui est connecté et avec quel token:

```bash
curl -H "Authorization: Bearer <ton_token>" http://localhost:5000/auth/me
```

### Résultat attendu
```json
{
  "user_id": 2,
  "role": "user",
  "payload": {
    "iat": 1708621411,
    "exp": 1708625011,
    "type": "scanner_token",
    "user_id": 2,
    "role": "user"
  }
}
```

---

## 🔍 Diagnostic Complet

### Flow de Connexion

1. **Register/Login** → `/auth/register` ou `/auth/login`
   ```json
   POST /auth/register
   {
     "email": "user2@example.com",
     "username": "user2",
     "password": "secure123"
   }
   → Retourne: { "token": "eyJ0...", "expiresIn": 3600 }
   ```

2. **Vérifier l'identité** → `/auth/me`
   ```bash
   Authorization: Bearer eyJ0...
   → Retourne: { "user_id": 2, "role": "user", ... }
   ```

3. **Lancer un scan** → `/scan` (avec le token JWT)
   ```json
   POST /scan
   Header: Authorization: Bearer eyJ0...
   Body: { "target": "http://example.com", ... }
   → ✅ Scan créé avec user_id=2
   ```

---

## 🛠️ Tests à Faire

### Test 1 : Vérifier l'utilisateur du token
```bash
TOKEN=$(curl -s http://localhost:5000/auth/token | jq -r '.token')
curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/auth/me
```
✅ Doit afficher `"user_id": 1` (user "system")

### Test 2 : Register + Test identité
```bash
TOKEN=$(curl -s -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","username":"test","password":"pass123"}' \
  | jq -r '.token')

curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/auth/me
```
✅ Doit afficher `"user_id": 2` (ou supérieur)

### Test 3 : Lancer un scan avec vrai utilisateur
```bash
# D'abord register/login pour obtenir token
# Puis faire un POST /scan avec ce token
# Vérifier en DB que scan_runs.user_id = votre user_id
```

---

## 🚀 Prochaines Étapes

1. **Frontend** : Vérifier que les tokens sont correctement stockés/envoyés
   - Voir `localStorage.getItem("token")`
   - Vérifier le header `Authorization: Bearer <token>` dans les appels `/scan`

2. **Database** : Vérifier les scans créés
   ```sql
   SELECT id, user_id, target, status, started_at FROM scan_runs LIMIT 10;
   ```
   Tous les `user_id` doivent être > 0 (pas de NULL)

3. **Logging** : Vérifier les logs d'audit
   ```sql
   SELECT user_id, scan_id, action, created_at FROM audit_logs LIMIT 20;
   ```
   Doit tracer qui a fait quoi

---

## 📝 Résumé des Imports/Dépendances

- **bcrypt** : Hachage des mots de passe ✅
- **jwt** : Génération/Validation des tokens JWT ✅
- **SQLAlchemy** : ORM pour User, ScanRun, AuditLog ✅
- **Flask** : Framework web ✅

Tous les imports et dépendances sont déjà en place.

