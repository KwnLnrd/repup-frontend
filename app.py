import os
import re
import json
import logging
import requests
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_current_user
from dateutil.parser import parse as parse_datetime
from apify_client import ApifyClient

# --- CONFIGURATION INITIALE ---
load_dotenv()
app = Flask(__name__)

# --- CONFIGURATION DU DOSSIER DE TÉLÉVERSEMENT ---
# Utilisation d'un chemin absolu pour la robustesse en production
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- LOGGING ---
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# --- CORS ---
CORS(app, origins=["*"], supports_credentials=True, allow_headers=["Authorization", "Content-Type"])

# --- CONFIGURATION BDD & JWT ---
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("DATABASE_URL is not set in .env file.")

# CORRECTION: S'assurer que SQLAlchemy utilise le driver 'psycopg' (v3) et non 'psycopg2'
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://") and "+psycopg" not in database_url:
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)


app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "une-cle-vraiment-secrete-et-longue-pour-la-prod")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

db = SQLAlchemy(app)
jwt = JWTManager(app)


# --- LISTE MAÎTRESSE DES TAGS PRÉ-TRADUITS ---
PRE_TRANSLATED_TAGS = {
    'service': [
        {'key': 'service_attentive', 'fr': 'Attentionné', 'en': 'Attentive', 'es': 'Atento'},
        {'key': 'service_smiling', 'fr': 'Souriant', 'en': 'Smiling', 'es': 'Sonriente'},
        {'key': 'service_professional', 'fr': 'Professionnel', 'en': 'Professional', 'es': 'Profesional'},
        {'key': 'service_efficient', 'fr': 'Efficace', 'en': 'Efficient', 'es': 'Eficiente'},
        {'key': 'service_good_advice', 'fr': 'De bon conseil', 'en': 'Good advice', 'es': 'Buen consejo'},
        {'key': 'service_discreet', 'fr': 'Discret', 'en': 'Discreet', 'es': 'Discreto'},
    ],
    'occasion': [
        {'key': 'occasion_birthday', 'fr': 'Anniversaire', 'en': 'Birthday', 'es': 'Cumpleaños'},
        {'key': 'occasion_romantic', 'fr': 'Dîner romantique', 'en': 'Romantic dinner', 'es': 'Cena romántica'},
        {'key': 'occasion_friends', 'fr': 'Entre amis', 'en': 'With friends', 'es': 'Con amigos'},
        {'key': 'occasion_family', 'fr': 'En famille', 'en': 'With family', 'es': 'En familia'},
        {'key': 'occasion_business', 'fr': 'Affaires', 'en': 'Business', 'es': 'Negocios'},
        {'key': 'occasion_visit', 'fr': 'Simple visite', 'en': 'Just visiting', 'es': 'Simple visita'},
    ],
    'atmosphere': [
        {'key': 'atmosphere_decoration', 'fr': 'La Décoration', 'en': 'The Decoration', 'es': 'La Decoración'},
        {'key': 'atmosphere_music', 'fr': 'La Musique', 'en': 'The Music', 'es': 'La Música'},
        {'key': 'atmosphere_festive', 'fr': 'L\'Énergie Festive', 'en': 'The Festive Energy', 'es': 'La Energía Festiva'},
        {'key': 'atmosphere_lighting', 'fr': 'L\'Éclairage', 'en': 'The Lighting', 'es': 'La Iluminación'},
        {'key': 'atmosphere_comfort', 'fr': 'Le Confort', 'en': 'The Comfort', 'es': 'La Comodidad'},
        {'key': 'atmosphere_romantic', 'fr': 'Romantique', 'en': 'Romantic', 'es': 'Romántico'},
    ]
}


# --- MODÈLES DE LA BASE DE DONNÉES ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False)
    restaurant = db.relationship('Restaurant', back_populates='user', uselist=False)

class Restaurant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    logo_url = db.Column(db.Text, nullable=True)
    primary_color = db.Column(db.String(7), default='#D69E2E')
    google_link = db.Column(db.Text, nullable=True)
    tripadvisor_link = db.Column(db.Text, nullable=True)
    enabled_languages = db.Column(db.JSON, default=['fr', 'en'])
    user = db.relationship('User', back_populates='restaurant', cascade="all, delete-orphan")
    servers = db.relationship('Server', back_populates='restaurant', cascade="all, delete-orphan")
    dishes = db.relationship('Dish', back_populates='restaurant', cascade="all, delete-orphan")
    tag_selections = db.relationship('RestaurantTag', back_populates='restaurant', cascade="all, delete-orphan")
    reviews = db.relationship('Review', back_populates='restaurant', cascade="all, delete-orphan")

class RestaurantTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    tag_key = db.Column(db.String(100), nullable=False, index=True) 
    restaurant = db.relationship('Restaurant', back_populates='tag_selections')

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    avatar_url = db.Column(db.Text, nullable=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='servers')

class Dish(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    restaurant = db.relationship('Restaurant', back_populates='dishes')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'), nullable=False, index=True)
    source = db.Column(db.String(20), nullable=False) # 'google', 'tripadvisor', 'internal'
    author_name = db.Column(db.String(100))
    rating = db.Column(db.Float, nullable=False)
    content = db.Column(db.Text)
    review_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    restaurant = db.relationship('Restaurant', back_populates='reviews')


with app.app_context():
    db.create_all()

# --- FONCTIONS HELPERS POUR LE SCRAPING ET LA SAUVEGARDE ---

def save_reviews_to_db(reviews_data, restaurant_id, source):
    """
    Sauvegarde une liste d'avis parsés dans la base de données, en évitant les doublons.
    """
    new_reviews_count = 0
    for review_item in reviews_data:
        # Vérification plus robuste pour éviter les doublons basés sur le contenu et l'auteur
        existing_review = Review.query.filter_by(
            restaurant_id=restaurant_id, 
            content=review_item.get('content'),
            author_name=review_item.get('author_name')
        ).first()

        if not existing_review and review_item.get('content'):
            new_review = Review(
                restaurant_id=restaurant_id,
                source=source,
                author_name=review_item.get('author_name'),
                rating=float(review_item.get('rating', 0)),
                content=review_item.get('content'),
                review_date=parse_datetime(review_item.get('review_date')) if review_item.get('review_date') else datetime.utcnow()
            )
            db.session.add(new_review)
            new_reviews_count += 1
    if new_reviews_count > 0:
        db.session.commit()
    app.logger.info(f"{new_reviews_count} nouveaux avis de '{source}' ont été ajoutés.")


def scrape_reviews_with_apify(actor_id, target_urls):
    """
    Lance un Actor Apify, attend la fin de l'exécution et retourne les résultats.
    """
    apify_token = os.getenv('APIFY_API_TOKEN')
    if not apify_token:
        app.logger.error("Le token API d'Apify (APIFY_API_TOKEN) est manquant dans le fichier .env.")
        return []

    try:
        client = ApifyClient(apify_token)
        # Configuration optimisée pour des résultats rapides et pertinents
        run_input = {
            "startUrls": [{"url": url} for url in target_urls],
            "maxReviews": 50, # On peut augmenter si besoin
            "language": "fr",
            "maxConcurrency": 5
        }
        
        app.logger.info(f"Lancement de l'Actor Apify '{actor_id}' pour les URLs: {target_urls}")
        run = client.actor(actor_id).call(run_input=run_input, wait_for_finish=120) # Attente max de 2 minutes
        
        app.logger.info(f"Récupération des résultats pour le run ID: {run['defaultDatasetId']}")
        items = list(client.dataset(run["defaultDatasetId"]).iterate_items())
        
        app.logger.info(f"{len(items)} résultats bruts récupérés de l'Actor '{actor_id}'.")
        return items

    except Exception as e:
        app.logger.error(f"Erreur lors de l'exécution de l'Actor Apify '{actor_id}': {e}")
        return []

def parse_apify_google_reviews(items):
    """
    Transforme les résultats bruts de l'Actor Google Maps en notre format standard.
    """
    parsed_reviews = []
    for item in items:
        # On s'assure que l'avis a du contenu textuel pour être utile
        if item.get('text'):
            parsed_reviews.append({
                'author_name': item.get('name', 'Utilisateur Google'),
                'rating': item.get('stars', 0),
                'content': item.get('text'),
                'review_date': item.get('publishedAtDate', str(datetime.utcnow()))
            })
    return parsed_reviews


# --- GESTION DE L'UTILISATEUR JWT ---
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=int(identity)).one_or_none()

def get_restaurant_id_from_token():
    current_user = get_current_user()
    if current_user:
        return current_user.restaurant_id
    return None

def generate_unique_slug(name, restaurant_id):
    base_slug = name.lower().replace(' ', '-')
    base_slug = re.sub(r'[^a-z0-9-]', '', base_slug)
    return f"{base_slug}-{restaurant_id}"

# --- ROUTES PUBLIQUES ---
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email, password, restaurant_name = data.get('email'), data.get('password'), data.get('restaurant_name')
    if not all([email, password, restaurant_name]): return jsonify({"error": "Données manquantes"}), 400
    if User.query.filter_by(email=email).first(): return jsonify({"error": "Cet email est déjà utilisé"}), 409
    
    new_restaurant = Restaurant(name=restaurant_name, slug="temporary-slug")
    db.session.add(new_restaurant)
    db.session.flush()

    new_restaurant.slug = generate_unique_slug(restaurant_name, new_restaurant.id)

    default_tag_keys = [tag['key'] for category in PRE_TRANSLATED_TAGS for tag in PRE_TRANSLATED_TAGS[category]]
    for key in default_tag_keys:
        db.session.add(RestaurantTag(restaurant_id=new_restaurant.id, tag_key=key))
    
    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password_hash=hashed_password, restaurant_id=new_restaurant.id)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Compte créé avec succès"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    return jsonify({"error": "Identifiants invalides"}), 401

@app.route('/api/public/restaurant/<string:slug>', methods=['GET'])
def get_restaurant_public_data(slug):
    restaurant = Restaurant.query.filter_by(slug=slug).first_or_404("Restaurant non trouvé")
    servers = Server.query.filter_by(restaurant_id=restaurant.id).all()
    
    selected_tag_keys = {tag.tag_key for tag in restaurant.tag_selections}
    
    tags_for_frontend = {}
    for category, tags_list in PRE_TRANSLATED_TAGS.items():
        tags_for_frontend[category] = []
        for tag_data in tags_list:
            if tag_data['key'] in selected_tag_keys:
                translations = {lang: tag_data.get(lang, tag_data['fr']) for lang in restaurant.enabled_languages}
                translations['fr'] = tag_data['fr'] # Assurer que le français est toujours là
                tags_for_frontend[category].append({
                    "key": tag_data['key'],
                    "translations": translations
                })

    return jsonify({
        "name": restaurant.name, "logoUrl": restaurant.logo_url, "primaryColor": restaurant.primary_color,
        "links": {"google": restaurant.google_link, "tripadvisor": restaurant.tripadvisor_link},
        "servers": [{"id": s.id, "name": s.name, "avatar": s.avatar_url} for s in servers],
        "languages": restaurant.enabled_languages,
        "tags": tags_for_frontend
    })

@app.route('/api/public/menu/<string:slug>', methods=['GET'])
def get_public_menu(slug):
    restaurant = Restaurant.query.filter_by(slug=slug).first_or_404()
    dishes = Dish.query.filter_by(restaurant_id=restaurant.id).all()
    
    menu_by_category = {}
    for dish in dishes:
        if dish.category not in menu_by_category:
            menu_by_category[dish.category] = []
        menu_by_category[dish.category].append({"id": dish.id, "name": dish.name})
    return jsonify(menu_by_category)

@app.route('/api/generate-review', methods=['POST'])
def generate_review_proxy():
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return jsonify({"error": "La clé API OpenAI n'est pas configurée sur le serveur."}), 500
    data = request.get_json()
    prompt = data.get('prompt')
    if not prompt:
        return jsonify({"error": "Le prompt est manquant."}), 400
    openai_url = 'https://api.openai.com/v1/chat/completions'
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'}
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "system", "content": "Tu es un assistant IA qui rédige des avis de restaurant positifs et engageants."}, {"role": "user", "content": prompt}]
    }
    try:
        response = requests.post(openai_url, headers=headers, json=payload, timeout=20)
        response.raise_for_status()
        openai_data = response.json()
        review_text = openai_data['choices'][0]['message']['content'].strip()
        return jsonify({"review": review_text})
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Erreur lors de l'appel à l'API OpenAI: {e}")
        return jsonify({"error": f"Erreur de communication avec l'API OpenAI: {e}"}), 502
    except (KeyError, IndexError) as e:
        app.logger.error(f"Réponse inattendue de l'API OpenAI: {openai_data}")
        return jsonify({"error": "Format de réponse inattendu de la part d'OpenAI."}), 500

# --- ROUTES PROTÉGÉES ---

@app.route('/api/restaurant', methods=['GET', 'PUT'])
@jwt_required()
def manage_restaurant_settings():
    restaurant_id = get_restaurant_id_from_token()
    restaurant = db.session.get(Restaurant, restaurant_id)
    if not restaurant: return jsonify({"error": "Restaurant non trouvé"}), 404
    
    if request.method == 'GET':
        return jsonify({
            "name": restaurant.name, "slug": restaurant.slug, "logoUrl": restaurant.logo_url,
            "primaryColor": restaurant.primary_color, "googleLink": restaurant.google_link,
            "tripadvisorLink": restaurant.tripadvisor_link, "enabledLanguages": restaurant.enabled_languages
        })
    
    elif request.method == 'PUT':
        data = request.form
        restaurant.name = data.get('name', restaurant.name)
        restaurant.primary_color = data.get('primaryColor', restaurant.primary_color)
        restaurant.google_link = data.get('googleLink', restaurant.google_link)
        restaurant.tripadvisor_link = data.get('tripadvisorLink', restaurant.tripadvisor_link)
        
        if 'enabledLanguages' in data:
            try:
                restaurant.enabled_languages = json.loads(data.get('enabledLanguages'))
            except json.JSONDecodeError:
                return jsonify({"error": "Format JSON invalide pour les langues"}), 400

        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                restaurant.logo_url = f'/uploads/{filename}'
        
        db.session.commit()
        return jsonify({"message": "Paramètres mis à jour", "logoUrl": restaurant.logo_url})

@app.route('/api/options', methods=['GET', 'POST'])
@jwt_required()
def manage_options():
    restaurant_id = get_restaurant_id_from_token()
    if request.method == 'GET':
        selected_tags = db.session.query(RestaurantTag.tag_key).filter_by(restaurant_id=restaurant_id).all()
        selected_keys = [key for (key,) in selected_tags]
        return jsonify({
            "available_tags": PRE_TRANSLATED_TAGS,
            "selected_keys": selected_keys
        })
    
    if request.method == 'POST':
        data = request.get_json()
        new_selected_keys = data.get('selected_keys', [])
        
        RestaurantTag.query.filter_by(restaurant_id=restaurant_id).delete()
        
        for key in new_selected_keys:
            db.session.add(RestaurantTag(restaurant_id=restaurant_id, tag_key=key))
            
        db.session.commit()
        return jsonify({"message": "Options mises à jour avec succès."}), 200

@app.route('/api/servers', methods=['GET', 'POST'])
@jwt_required()
def manage_servers():
    restaurant_id = get_restaurant_id_from_token()
    if request.method == 'GET':
        servers = Server.query.filter_by(restaurant_id=restaurant_id).order_by(Server.name).all()
        return jsonify([{"id": s.id, "name": s.name, "avatar_url": s.avatar_url} for s in servers])
    if request.method == 'POST':
        name = request.form.get('name')
        if not name: return jsonify({"error": "Le nom est requis"}), 400
        avatar_url = None
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                avatar_url = f'/uploads/{filename}'
        new_server = Server(name=name, avatar_url=avatar_url, restaurant_id=restaurant_id)
        db.session.add(new_server)
        db.session.commit()
        return jsonify({"id": new_server.id, "name": new_server.name, "avatar_url": new_server.avatar_url}), 201

@app.route('/api/servers/<int:server_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def manage_single_server(server_id):
    restaurant_id = get_restaurant_id_from_token()
    server = Server.query.filter_by(id=server_id, restaurant_id=restaurant_id).first_or_404()
    if request.method == 'PUT':
        server.name = request.form.get('name', server.name)
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{datetime.utcnow().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                server.avatar_url = f'/uploads/{filename}'
        db.session.commit()
        return jsonify({"id": server.id, "name": server.name, "avatar_url": server.avatar_url})
    if request.method == 'DELETE':
        db.session.delete(server)
        db.session.commit()
        return '', 204

@app.route('/api/menu', methods=['GET', 'POST'])
@jwt_required()
def manage_menu():
    restaurant_id = get_restaurant_id_from_token()
    if request.method == 'GET':
        dishes = Dish.query.filter_by(restaurant_id=restaurant_id).order_by(Dish.category, Dish.name).all()
        menu_by_category = {}
        for dish in dishes:
            if dish.category not in menu_by_category: menu_by_category[dish.category] = []
            menu_by_category[dish.category].append({"id": dish.id, "name": dish.name})
        return jsonify(menu_by_category)
    if request.method == 'POST':
        data = request.get_json()
        if not data.get('name') or not data.get('category'):
            return jsonify({"error": "Le nom et la catégorie sont requis"}), 400
        new_dish = Dish(name=data['name'], category=data['category'], restaurant_id=restaurant_id)
        db.session.add(new_dish)
        db.session.commit()
        return jsonify({"id": new_dish.id, "name": new_dish.name, "category": new_dish.category}), 201

@app.route('/api/menu/<int:dish_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def manage_single_dish(dish_id):
    restaurant_id = get_restaurant_id_from_token()
    dish = Dish.query.filter_by(id=dish_id, restaurant_id=restaurant_id).first_or_404()
    if request.method == 'PUT':
        data = request.get_json()
        dish.name = data.get('name', dish.name)
        dish.category = data.get('category', dish.category)
        db.session.commit()
        return jsonify({"id": dish.id, "name": dish.name, "category": dish.category})
    if request.method == 'DELETE':
        db.session.delete(dish)
        db.session.commit()
        return '', 204

# --- NOUVELLE ROUTE D'ANALYSE STRATÉGIQUE ---
@app.route('/api/strategic-analysis', methods=['POST'])
@jwt_required()
def trigger_strategic_analysis():
    restaurant_id = get_restaurant_id_from_token()
    restaurant = db.session.get(Restaurant, restaurant_id)
    if not restaurant:
        return jsonify({"error": "Restaurant non trouvé"}), 404

    app.logger.info(f"Début de l'analyse stratégique pour le restaurant ID: {restaurant_id} ({restaurant.name})")

    # Étape 1: Nettoyer les anciens avis scrapés pour rafraîchir les données
    app.logger.info("Nettoyage des anciens avis externes...")
    Review.query.filter(
        Review.restaurant_id == restaurant_id,
        Review.source.in_(['google', 'tripadvisor'])
    ).delete()
    db.session.commit()

    # Étape 2: Lancer le scraping des nouvelles données
    if restaurant.google_link:
        app.logger.info(f"Lien Google trouvé: {restaurant.google_link}. Lancement du scraping.")
        # L'ID de l'actor peut être stocké en variable d'environnement pour plus de flexibilité
        actor_id = os.getenv("GOOGLE_MAPS_ACTOR_ID", "apify/google-maps-reviews-scraper")
        raw_google_reviews = scrape_reviews_with_apify(actor_id, [restaurant.google_link])
        if raw_google_reviews:
            parsed_reviews = parse_apify_google_reviews(raw_google_reviews)
            save_reviews_to_db(parsed_reviews, restaurant_id, 'google')
            app.logger.info(f"{len(parsed_reviews)} avis Google ont été traités.")
    else:
        app.logger.warning("Aucun lien Google configuré pour ce restaurant.")
    
    # (Optionnel) Ajouter le scraping TripAdvisor ici sur le même modèle
    # if restaurant.tripadvisor_link: ...

    # Étape 3: Récupérer tous les avis (internes + externes)
    all_reviews = Review.query.filter_by(restaurant_id=restaurant_id).order_by(Review.created_at.desc()).all()
    if not all_reviews:
        return jsonify({"error": "Aucun avis (interne ou externe) n'a été trouvé pour générer une analyse. Assurez-vous que vos liens de scraping sont corrects ou que vous avez des avis internes."}), 404

    app.logger.info(f"Total de {len(all_reviews)} avis trouvés pour l'analyse.")
    review_contents = [r.content for r in all_reviews if r.content]

    # Étape 4: Préparer le prompt pour l'IA
    prompt = f"""
    En tant que consultant expert pour restaurants, analyse la liste d'avis suivante pour le restaurant "{restaurant.name}".
    Fournis une analyse stratégique complète au format JSON. Le JSON doit être valide et contenir uniquement les clés demandées.

    Voici les avis (les plus récents en premier) :
    {json.dumps(review_contents[:100])}

    ---
    En te basant sur ces avis, fournis les éléments suivants dans un objet JSON unique :
    1.  "executive_summary": Un résumé percutant de 2-3 phrases sur les tendances générales, les points forts et les faiblesses.
    2.  "strengths": Une liste de 3 à 5 points forts majeurs, cités de manière récurrente.
    3.  "weaknesses": Une liste de 3 à 5 axes d'amélioration prioritaires, basés sur les critiques fréquentes.
    4.  "opportunities": Une liste de 2-3 "pépites" ou opportunités inattendues (suggestions de clients, compliments sur des détails, etc.).
    5.  "proactive_suggestions": Une liste de 3 suggestions concrètes et actionnables (Marketing, Opérationnel, Management). Formatte chaque suggestion comme "Catégorie: Suggestion détaillée.".
    """
    
    # Étape 5: Appeler l'API d'IA
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key: 
        app.logger.error("Clé API OpenAI manquante.")
        return jsonify({"error": "La clé API pour l'IA n'est pas configurée sur le serveur."}), 500

    openai_url = 'https://api.openai.com/v1/chat/completions'
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'}
    # Utilisation de gpt-4-turbo pour une meilleure qualité d'analyse et le support du format JSON
    payload = { 
        "model": "gpt-4-turbo", 
        "messages": [{"role": "user", "content": prompt}], 
        "response_format": { "type": "json_object" } 
    }
    try:
        app.logger.info("Envoi de la requête à l'API OpenAI...")
        response = requests.post(openai_url, headers=headers, json=payload, timeout=90) # Timeout plus long pour l'analyse
        response.raise_for_status()
        
        # Le contenu est déjà un objet JSON grâce à "json_object"
        analysis_data = json.loads(response.json()['choices'][0]['message']['content'])
        app.logger.info("Analyse stratégique générée avec succès.")
        return jsonify(analysis_data)
    except requests.exceptions.Timeout:
        app.logger.error("Timeout lors de l'appel à l'API OpenAI.")
        return jsonify({"error": "La génération de l'analyse a pris trop de temps. Veuillez réessayer."}), 504
    except Exception as e:
        app.logger.error(f"Erreur lors de l'appel à l'API OpenAI: {e}")
        return jsonify({"error": "Une erreur est survenue lors de la communication avec le service d'intelligence artificielle."}), 502


if __name__ == '__main__':
    # Utilisation de Gunicorn recommandée pour la production, mais pour le dev local :
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
