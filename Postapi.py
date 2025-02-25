import sqlite3
import bcrypt
from flask import Flask, request, jsonify
import re
from email_validator import validate_email, EmailNotValidError
import sqlitecloud
from dotenv import load_dotenv
import os

app = Flask(__name__)
load_dotenv()
# Funktion zum Herstellen der Verbindung zur SQLite-Datenbank
def get_db_connection():
    conn = sqlitecloud.connect(os.getenv("CONNECTION_STRING"))
    conn.row_factory = sqlite3.Row  # Damit Ergebnisse als Dictionary zurückgegeben werden
    return conn

@app.route("/", methods=["GET"])
def hello_world():
    return "Hello, World!", 200

#Löschen
@app.route("/löschen", methods=["POST"])
def delete_user():
    conn = sqlite3.connect('C:\\sqlite\\Users.db')
    cur = conn.cursor()
    username = request.json.get('username')

    if not username:
        return jsonify({'error': 'Kein Benutzername angegeben!'}), 400

    try:
        # Lösche den Benutzer basierend auf dem Benutzernamen
        cur.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        
        if cur.rowcount > 0:
            return jsonify({'message': f"Benutzer '{username}' erfolgreich gelöscht."}), 200
        else:
            return jsonify({'error': f"Benutzer '{username}' nicht gefunden!"}), 404
    except sqlite3.Error as e:
        return jsonify({'error': f'Fehler beim Löschen: {e}'}), 500
    finally:
        cur.close()
        conn.close()




#Adminaktualisierung


@app.route('/admin', methods=['POST'])
def set_admin_status():
    # Extrahiere den Benutzernamen aus dem JSON-Body
    data = request.get_json()
    username = data.get('username') if data else None

    if not username:
        return jsonify({"error": "Benutzername muss angegeben werden!"}), 400

    try:
        with sqlite3.connect("CONNECTION_STRING") as conn:
            cur = conn.cursor()
            # Adminstatus auf TRUE (1) setzen
            cur.execute("UPDATE users SET admin = ? WHERE username = ?", (True, username))
            conn.commit()

            if cur.rowcount > 0:
                return jsonify({'message': f"Adminstatus von '{username}' erfolgreich auf True gesetzt."}), 200
            else:
                return jsonify({"error": f"Benutzer '{username}' nicht gefunden."}), 404
    except sqlite3.Error as e:
        return jsonify({"error": f"Fehler beim Aktualisieren der Adminrechte: {str(e)}"}), 500



@app.route('/radmin', methods=['POST'])
def set_radmin_status():
    # Extrahiere den Benutzernamen aus dem JSON-Body
    data = request.get_json()
    username = data.get('username') if data else None
    

    if not username:
        return jsonify({"error": "Benutzername muss angegeben werden!"}), 400

    try:
        with sqlite3.connect("CONNECTION_STRING") as conn:
            cur = conn.cursor()
            # Adminstatus auf TRUE (1) setzen
            cur.execute("UPDATE users SET admin = ? WHERE username = ?", (False, username))
            conn.commit()

            if cur.rowcount > 0:
                return jsonify({'message': f"Adminstatus von '{username}' erfolgreich auf False gesetzt."}), 200
            else:
                return jsonify({"error": f"Benutzer '{username}' nicht gefunden."}), 404
    except sqlite3.Error as e:
        return jsonify({"error": f"Fehler beim Aktualisieren der Adminrechte: {str(e)}"}), 500

# Route für die Benutzerregistrierung (POST-Anfrage)
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')

    # Sicherstellen, dass die Felder nicht leer sind
    if not username or not password or not email:
        return jsonify({'error': 'Fehlende Parameter'}), 400
    
    try:

 
        emailinfo = validate_email(email, check_deliverability=False)
        email = emailinfo.normalized

    except EmailNotValidError as e:

        print(str(e))
        return jsonify({'error': 'Diese E-Mail ist nicht verfügbar'}), 400

    # Passwort in einen Hash umwandeln
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    try:
        # Benutzer in die Tabelle einfügen
        conn.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                     (username, hashed_password, email))
        conn.commit()
        return jsonify({'message': 'Benutzer erfolgreich registriert!', username: username, email: email}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Benutzername oder E-Mail existiert bereits.'}), 400
    finally:
        conn.close()



# Route für die Benutzeranmeldung (POST-Anfrage)
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'error': 'Fehlende Parameter'}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    # Prüfen, ob der Benutzer existiert
    cur.execute("SELECT password, admin FROM users WHERE username = ?", (username,))
    result = cur.fetchone()

    if result:
        stored_hashed_password, admin_status = result  # Passwort und Adminstatus auslesen

        # Passwort prüfen
        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
            # E-Mail aus der Datenbank abrufen
            cur.execute("SELECT email FROM users WHERE username = ?", (username,))
            email_result = cur.fetchone()
            email = email_result[0] if email_result else None

            conn.close()
            return jsonify({
                'message': 'Benutzer erfolgreich authentifiziert!',
                'username': username,
                'email': email,
                'admin': admin_status  # Adminstatus als Boolean zurückgeben
            }), 200
        else:
            conn.close()
            return jsonify({'error': 'Falsches Passwort'}), 401
    else:
        conn.close()
        return jsonify({'error': 'Benutzername nicht gefunden.'}), 404
    
    

if __name__ == '__main__':
    app.run(debug=True)