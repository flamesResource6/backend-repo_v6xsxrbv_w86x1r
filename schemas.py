"""
Application Schemas for TransPublic — Gestion du parc automobile

Each Pydantic model represents a collection in MongoDB.
Collection name is the lowercase class name.
"""
from __future__ import annotations
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr
from datetime import date, datetime

# -----------------
# Auth & Users
# -----------------
class UserCreate(BaseModel):
    nom: str
    email: EmailStr
    mot_de_passe: str
    role: Literal["admin", "gestionnaire", "agent"] = "agent"
    departement: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    mot_de_passe: str

class UserOut(BaseModel):
    id: str
    nom: str
    email: EmailStr
    role: str
    departement: Optional[str] = None

class User(BaseModel):
    nom: str
    email: EmailStr
    mot_de_passe_hash: str
    role: Literal["admin", "gestionnaire", "agent"] = "agent"
    departement: Optional[str] = None
    is_active: bool = True

# -----------------
# Vehicles
# -----------------
class Vehicle(BaseModel):
    immatriculation: str
    marque: str
    modele: str
    annee: int
    kilometrage_initial: int = Field(ge=0)
    type: Literal["voiture", "utilitaire"]
    statut: Literal["actif", "inactif", "maintenance", "assigne"] = "actif"
    departement: Optional[str] = None
    notes: Optional[str] = None
    deleted_at: Optional[datetime] = None

# -----------------
# Assignments
# -----------------
class Assignment(BaseModel):
    vehicule_id: str
    utilisateur_id: str
    date_debut: date
    date_fin_prevue: Optional[date] = None
    date_fin_reelle: Optional[date] = None
    kilometrage_debut: Optional[int] = Field(default=None, ge=0)
    kilometrage_fin: Optional[int] = Field(default=None, ge=0)
    motif: Optional[str] = None

# -----------------
# Maintenance
# -----------------
class Maintenance(BaseModel):
    vehicule_id: str
    date: date
    type: Literal["revision", "reparation"]
    garage: Optional[str] = None
    cout: float = Field(ge=0)
    description: Optional[str] = None
    pieces_remplacees: Optional[List[str]] = None
    kilometrage: Optional[int] = Field(default=None, ge=0)

# -----------------
# Insurance
# -----------------
class Insurance(BaseModel):
    vehicule_id: str
    assureur: str
    numero_contrat: str
    date_debut: date
    date_fin: date
    prime: float = Field(ge=0)
    fichier_document: Optional[str] = None  # stored file path

# -----------------
# Fuel Consumption
# -----------------
class FuelConsumption(BaseModel):
    vehicule_id: str
    date: date
    kilometrage: int = Field(ge=0)
    litres: float = Field(ge=0)
    cout: float = Field(ge=0)

# -----------------
# Settings & Alerts
# -----------------
class Settings(BaseModel):
    alert_threshold_days: int = 30

# -----------------
# History logging
# -----------------
class History(BaseModel):
    entity: str
    entity_id: str
    action: Literal["create", "update", "delete", "restore"]
    user_id: Optional[str] = None
    payload: Optional[dict] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
