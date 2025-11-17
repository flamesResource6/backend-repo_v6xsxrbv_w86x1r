import os
from datetime import datetime, timedelta, date
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents
from bson import ObjectId

from schemas import (
    UserCreate, UserLogin, UserOut, User, Vehicle, Assignment, Maintenance,
    Insurance, FuelConsumption, Settings, History
)

# ----------------------------
# Config & Globals
# ----------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="TransPublic — Gestion du parc automobile")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ----------------------------
# Helpers
# ----------------------------

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def to_object_id(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")

def collection(name: str):
    return db[name]


def create_history(entity: str, entity_id: str, action: str, user_id: Optional[str], payload: Optional[dict] = None):
    collection("history").insert_one({
        "entity": entity,
        "entity_id": entity_id,
        "action": action,
        "user_id": user_id,
        "payload": payload or {},
        "timestamp": datetime.utcnow()
    })


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


# ----------------------------
# Auth
# ----------------------------
@app.post("/auth/register", response_model=UserOut)
def register(user: UserCreate):
    if collection("user").find_one({"email": user.email}):
        raise HTTPException(400, "Email déjà utilisé")
    doc = user.model_dump()
    doc["mot_de_passe_hash"] = hash_password(doc.pop("mot_de_passe"))
    res = collection("user").insert_one(doc)
    uid = str(res.inserted_id)
    create_history("user", uid, "create", uid, {"email": user.email})
    return UserOut(id=uid, nom=user.nom, email=user.email, role=user.role, departement=user.departement)


@app.post("/auth/login", response_model=TokenOut)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = collection("user").find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user.get("mot_de_passe_hash", "")):
        raise HTTPException(401, "Identifiants invalides")
    payload = {
        "sub": str(user["_id"]),
        "role": user.get("role", "agent"),
        "exp": datetime.utcnow() + timedelta(hours=12)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    user_out = UserOut(id=str(user["_id"]), nom=user.get("nom"), email=user.get("email"), role=user.get("role"), departement=user.get("departement"))
    return TokenOut(access_token=token, user=user_out)


def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        uid = payload.get("sub")
        user = collection("user").find_one({"_id": ObjectId(uid)})
        if not user:
            raise HTTPException(401, "Utilisateur introuvable")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expirée")
    except Exception:
        raise HTTPException(401, "Token invalide")


def require_roles(*roles):
    def wrapper(user=Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(403, "Accès refusé")
        return user
    return wrapper


# ----------------------------
# Vehicles CRUD + filters + soft delete
# ----------------------------
@app.post("/vehicles")
def create_vehicle(v: Vehicle, user=Depends(require_roles("admin", "gestionnaire"))):
    if collection("vehicle").find_one({"immatriculation": v.immatriculation, "deleted_at": {"$eq": None}}):
        raise HTTPException(400, "Immatriculation déjà utilisée")
    doc = v.model_dump()
    res = collection("vehicle").insert_one(doc)
    vid = str(res.inserted_id)
    create_history("vehicle", vid, "create", str(user["_id"]), doc)
    return {"id": vid, **doc}

@app.get("/vehicles")
def list_vehicles(q: Optional[str] = None, statut: Optional[str] = None, departement: Optional[str] = None, skip: int = 0, limit: int = 50, user=Depends(get_current_user)):
    f: Dict[str, Any] = {"deleted_at": None}
    if q:
        f["$or"] = [
            {"immatriculation": {"$regex": q, "$options": "i"}},
            {"marque": {"$regex": q, "$options": "i"}},
            {"modele": {"$regex": q, "$options": "i"}},
        ]
    if statut:
        f["statut"] = statut
    if departement:
        f["departement"] = departement
    items = list(collection("vehicle").find(f).skip(skip).limit(limit))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items

@app.get("/vehicles/{vehicle_id}")
def get_vehicle(vehicle_id: str, user=Depends(get_current_user)):
    v = collection("vehicle").find_one({"_id": to_object_id(vehicle_id)})
    if not v:
        raise HTTPException(404, "Véhicule introuvable")
    v["id"] = str(v.pop("_id"))
    return v

@app.put("/vehicles/{vehicle_id}")
def update_vehicle(vehicle_id: str, v: Vehicle, user=Depends(require_roles("admin", "gestionnaire"))):
    doc = v.model_dump()
    res = collection("vehicle").update_one({"_id": to_object_id(vehicle_id)}, {"$set": doc})
    if res.matched_count == 0:
        raise HTTPException(404, "Véhicule introuvable")
    create_history("vehicle", vehicle_id, "update", str(user["_id"]), doc)
    return {"id": vehicle_id, **doc}

@app.delete("/vehicles/{vehicle_id}")
def delete_vehicle(vehicle_id: str, user=Depends(require_roles("admin", "gestionnaire"))):
    res = collection("vehicle").update_one({"_id": to_object_id(vehicle_id)}, {"$set": {"deleted_at": datetime.utcnow()}})
    if res.matched_count == 0:
        raise HTTPException(404, "Véhicule introuvable")
    create_history("vehicle", vehicle_id, "delete", str(user["_id"]))
    return {"status": "deleted"}


# ----------------------------
# Assignments
# ----------------------------
@app.post("/assignments")
def create_assignment(a: Assignment, user=Depends(require_roles("admin", "gestionnaire"))):
    # prevent overlap
    overlaps = collection("assignment").find_one({
        "vehicule_id": a.vehicule_id,
        "$or": [
            {"date_fin_reelle": None},
            {"date_fin_reelle": {"$exists": False}}
        ],
        "date_debut": {"$lte": a.date_fin_prevue or a.date_debut},
    })
    if overlaps:
        raise HTTPException(400, "Chevauchement d'affectation pour ce véhicule")

    doc = a.model_dump()
    res = collection("assignment").insert_one(doc)
    aid = str(res.inserted_id)
    # update vehicle status
    collection("vehicle").update_one({"_id": ObjectId(a.vehicule_id)}, {"$set": {"statut": "assigne"}})
    create_history("assignment", aid, "create", str(user["_id"]), doc)
    return {"id": aid, **doc}

@app.post("/assignments/{assignment_id}/close")
def close_assignment(assignment_id: str, kilometrage_fin: Optional[int] = None, date_fin_reelle: Optional[date] = None, user=Depends(require_roles("admin", "gestionnaire"))):
    upd: Dict[str, Any] = {"date_fin_reelle": date_fin_reelle or date.today()}
    if kilometrage_fin is not None:
        upd["kilometrage_fin"] = kilometrage_fin
    res = collection("assignment").update_one({"_id": to_object_id(assignment_id)}, {"$set": upd})
    if res.matched_count == 0:
        raise HTTPException(404, "Affectation introuvable")
    a = collection("assignment").find_one({"_id": to_object_id(assignment_id)})
    # Vehicle set to actif after return
    collection("vehicle").update_one({"_id": ObjectId(a["vehicule_id"])}, {"$set": {"statut": "actif"}})
    create_history("assignment", assignment_id, "update", str(user["_id"]), upd)
    return {"status": "closed"}

@app.get("/assignments")
def list_assignments(vehicule_id: Optional[str] = None, utilisateur_id: Optional[str] = None, user=Depends(get_current_user)):
    f: Dict[str, Any] = {}
    if vehicule_id:
        f["vehicule_id"] = vehicule_id
    if utilisateur_id:
        f["utilisateur_id"] = utilisateur_id
    items = list(collection("assignment").find(f).sort("date_debut", 1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# ----------------------------
# Maintenance
# ----------------------------
@app.post("/maintenances")
def create_maintenance(m: Maintenance, user=Depends(require_roles("admin", "gestionnaire"))):
    doc = m.model_dump()
    res = collection("maintenance").insert_one(doc)
    mid = str(res.inserted_id)
    # set vehicle maintenance status if date is today or past and type reparation
    if m.date <= date.today():
        collection("vehicle").update_one({"_id": ObjectId(m.vehicule_id)}, {"$set": {"statut": "maintenance"}})
    create_history("maintenance", mid, "create", str(user["_id"]), doc)
    return {"id": mid, **doc}

@app.get("/maintenances")
def list_maintenances(vehicule_id: Optional[str] = None, start: Optional[date] = None, end: Optional[date] = None, user=Depends(get_current_user)):
    f: Dict[str, Any] = {}
    if vehicule_id:
        f["vehicule_id"] = vehicule_id
    if start or end:
        f["date"] = {}
        if start:
            f["date"]["$gte"] = start
        if end:
            f["date"]["$lte"] = end
    items = list(collection("maintenance").find(f).sort("date", -1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# ----------------------------
# Insurance with file upload
# ----------------------------
@app.post("/insurances")
def create_insurance(
    vehicule_id: str = Form(...),
    assureur: str = Form(...),
    numero_contrat: str = Form(...),
    date_debut: str = Form(...),
    date_fin: str = Form(...),
    prime: float = Form(...),
    fichier_document: Optional[UploadFile] = File(None),
    user=Depends(require_roles("admin", "gestionnaire"))
):
    stored_path = None
    if fichier_document is not None:
        filename = f"{datetime.utcnow().timestamp()}_{fichier_document.filename}"
        stored_path = os.path.join(UPLOAD_DIR, filename)
        with open(stored_path, "wb") as f:
            f.write(fichier_document.file.read())
    doc = {
        "vehicule_id": vehicule_id,
        "assureur": assureur,
        "numero_contrat": numero_contrat,
        "date_debut": date.fromisoformat(date_debut),
        "date_fin": date.fromisoformat(date_fin),
        "prime": float(prime),
        "fichier_document": stored_path,
    }
    res = collection("insurance").insert_one(doc)
    iid = str(res.inserted_id)
    create_history("insurance", iid, "create", str(user["_id"]), doc)
    return {"id": iid, **doc}

@app.get("/insurances")
def list_insurances(vehicule_id: Optional[str] = None, user=Depends(get_current_user)):
    f: Dict[str, Any] = {}
    if vehicule_id:
        f["vehicule_id"] = vehicule_id
    items = list(collection("insurance").find(f).sort("date_fin", 1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items

@app.get("/insurances/{insurance_id}/download")
def download_insurance(insurance_id: str, user=Depends(get_current_user)):
    ins = collection("insurance").find_one({"_id": to_object_id(insurance_id)})
    if not ins or not ins.get("fichier_document"):
        raise HTTPException(404, "Document introuvable")
    return FileResponse(ins["fichier_document"], filename=os.path.basename(ins["fichier_document"]))


# ----------------------------
# Fuel
# ----------------------------
@app.post("/fuels")
def add_fuel(fc: FuelConsumption, user=Depends(require_roles("admin", "gestionnaire"))):
    doc = fc.model_dump()
    res = collection("fuelconsumption").insert_one(doc)
    fid = str(res.inserted_id)
    create_history("fuelconsumption", fid, "create", str(user["_id"]), doc)
    return {"id": fid, **doc}

@app.get("/fuels")
def list_fuels(vehicule_id: Optional[str] = None, user=Depends(get_current_user)):
    f: Dict[str, Any] = {}
    if vehicule_id:
        f["vehicule_id"] = vehicule_id
    items = list(collection("fuelconsumption").find(f).sort("date", -1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# ----------------------------
# Dashboard & Reports
# ----------------------------
@app.get("/dashboard")
def dashboard(user=Depends(get_current_user)):
    total = collection("vehicle").count_documents({"deleted_at": None})
    actifs = collection("vehicle").count_documents({"statut": "actif", "deleted_at": None})
    en_maint = collection("vehicle").count_documents({"statut": "maintenance", "deleted_at": None})

    # this month costs
    start = date.today().replace(day=1)
    maint_costs = collection("maintenance").aggregate([
        {"$match": {"date": {"$gte": start}}},
        {"$group": {"_id": None, "total": {"$sum": "$cout"}}}
    ])
    total_cost = 0.0
    for z in maint_costs:
        total_cost = float(z.get("total", 0))

    interventions = collection("maintenance").count_documents({"date": {"$gte": start}})

    # insurance alerts
    settings = collection("settings").find_one({}) or {"alert_threshold_days": 30}
    threshold = int(settings.get("alert_threshold_days", 30))
    alert_date = date.today() + timedelta(days=threshold)
    alerts = list(collection("insurance").find({"date_fin": {"$lte": alert_date}}))
    for a in alerts:
        a["id"] = str(a.pop("_id"))

    return {
        "nombre_vehicules": total,
        "vehicules_actifs": actifs,
        "vehicules_en_maintenance": en_maint,
        "couts_entretiens_mois": total_cost,
        "nombre_interventions_mois": interventions,
        "assurances_a_risque": alerts,
    }


@app.get("/reports/maintenance-costs")
def report_maintenance_costs(start: date, end: date, user=Depends(require_roles("admin", "gestionnaire"))):
    pipeline = [
        {"$match": {"date": {"$gte": start, "$lte": end}}},
        {"$group": {"_id": "$vehicule_id", "total": {"$sum": "$cout"}}}
    ]
    rows = list(collection("maintenance").aggregate(pipeline))
    for r in rows:
        r["vehicule_id"] = r.pop("_id")
    return rows

@app.get("/reports/vehicles-by-dept")
def report_vehicles_by_dept(user=Depends(get_current_user)):
    pipeline = [
        {"$match": {"deleted_at": None}},
        {"$group": {"_id": "$departement", "count": {"$sum": 1}}}
    ]
    rows = list(collection("vehicle").aggregate(pipeline))
    return [{"departement": r.get("_id"), "count": r.get("count")} for r in rows]

@app.get("/reports/assignments-history")
def report_assignments_history(vehicule_id: Optional[str] = None, user=Depends(get_current_user)):
    f: Dict[str, Any] = {}
    if vehicule_id:
        f["vehicule_id"] = vehicule_id
    items = list(collection("assignment").find(f).sort("date_debut", -1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# ----------------------------
# Settings
# ----------------------------
@app.get("/settings", response_model=Settings)
def get_settings(user=Depends(require_roles("admin", "gestionnaire"))):
    s = collection("settings").find_one({}) or {"alert_threshold_days": 30}
    return Settings(**s)

@app.put("/settings", response_model=Settings)
def update_settings(s: Settings, user=Depends(require_roles("admin"))):
    collection("settings").update_one({}, {"$set": s.model_dump()}, upsert=True)
    return s


# ----------------------------
# Utility
# ----------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


# Keep /test from template to validate DB connectivity
@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
