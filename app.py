"""
app.py — a small Flask API for the Velabahleke High School website.

WHAT THIS DOES
--------------
This file currently has two jobs:

1. Receive messages submitted through the contact form on contact.html,
   check that they look valid, and save them to contact_messages.json.

2. Receive Grade 8 enrolment applications submitted through the form on
   enrolment.html, including two uploaded files (report card, ID copy),
   check that everything required is present, save the files to disk,
   and save a record of the application to enrolments.json.

Both use the same simple pattern: store details as JSON, one entry per
submission. This mirrors the "store as JSON, load with a small storage
class" pattern from the TaskManager exercise — simple to read, and easy
to swap for a real database (like SQLite) later.

HOW TO RUN THIS
----------------
1. Install dependencies:  pip install -r requirements.txt
2. Run the server:         python app.py
3. Open contact.html or enrolment.html in a browser and submit a form —
   it will POST to this API.

Both frontend pages expect this server to be running at
http://127.0.0.1:5000 — see the API_URL constant in each file's <script>.

A new "uploads/" folder will be created automatically the first time
someone submits the enrolment form, to store uploaded files.

KNOWN ISSUES (found while reviewing this code — not yet fixed)
-----------------------------------------------------------------
1. Partial save on failure: submit_enrolment() saves the report file
   and the ID file as two separate steps. If the first save succeeds
   but the second one fails, the first file is left sitting in
   uploads/ with no matching record in enrolments.json.

2. Lost updates under concurrent submissions: load_json_list() reads
   the whole file, then save_json_list() writes the whole file back.
   If two people submit at almost the same moment, both might read
   the file before either writes back — whichever save happens last
   "wins", and the other person's submission is silently lost with no
   error shown to them.

3. File type is only checked by filename extension (allowed_file()),
   not by actually inspecting the file's content. Someone could rename
   any file to end in ".pdf" and it would pass this check.

4. EMAIL_PATTERN is a rough shape check, not a real email validator —
   it can let some malformed addresses through. This is a known,
   accepted trade-off, not an oversight.

5. No rate limiting or spam protection — nothing stops the same
   person (or a bot) from submitting the form many times in a row.

6. GET /api/contact, GET /api/enrolment, and GET /uploads/<file> are now
   protected by a simple login (see STAFF LOGIN below), but see that
   section's own limitations before treating this as production-ready.

STAFF LOGIN (added to fix issue #6 above)
-------------------------------------------
POST /api/login with {"username": ..., "password": ...} checks the
credentials and, if correct, returns a random token:
    {"token": "a1b2c3..."}

That token must then be sent with every request to a protected route,
as an HTTP header:
    Authorization: Bearer a1b2c3...

POST /api/logout invalidates a token so it can no longer be used.

Staff accounts are stored in staff_users.json, as a dict of
    {"username": "<hashed password>"}
A default account (admin / changeme123) is created automatically the
first time this file runs, if staff_users.json doesn't exist yet.
CHANGE THIS DEFAULT PASSWORD as soon as you can log in — see the
"Manage Staff" page (manage_staff.html), which lets a logged-in staff
member add new accounts.

LIMITATIONS OF THIS LOGIN SYSTEM (be aware before relying on it):
- Any logged-in staff member can add other staff accounts — there's no
  separate "admin vs regular staff" distinction. For a small school
  office this is usually fine, but it means everyone with a login has
  equal power to create more logins.
- There's no way to tell which staff member did what (no per-user
  activity log).
- Valid tokens are stored only in memory (VALID_TOKENS). Restarting the
  server logs every staff member out, and tokens never expire on their
  own.
- No protection against repeated failed login attempts (no lockout,
  no rate limiting) — someone could try to guess the password
  automatically.
- This is running over plain HTTP in development, not HTTPS. Sending a
  password over plain HTTP means it could be read by anyone on the
  same network. This MUST use HTTPS before going live.
These are reasonable for a school learning project, but a real
deployment should use a proper user/session system with password
hashing (already done here), token expiry, and HTTPS.
"""

import json
import os
import re
import secrets
import uuid
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)  # allows the HTML pages (opened as local files) to call this API

MESSAGES_FILE = "contact_messages.json"
ENROLMENTS_FILE = "enrolments.json"
UPLOAD_FOLDER = "uploads"

# Only these file types are accepted for uploads, matching what the
# enrolment.html form's accept="" attribute already advertises to users.
# The server re-checks this because a browser's accept attribute is only
# a hint — it doesn't stop someone from uploading a different file type.
ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png"}

# 5 MB per file — generous for a scanned report card or ID photo, small
# enough to avoid someone accidentally (or deliberately) uploading
# something huge.
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

# A simple, not-perfect email pattern check — good enough to catch obvious
# typos, not meant to be a full email validator.
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --- Staff login (see STAFF LOGIN in the module docstring for details) ---
STAFF_USERS_FILE = "staff_users.json"

# Tokens for currently logged-in staff. Lives only in memory: restarting
# the server clears every token (logs everyone out), and tokens never
# expire on their own. Fine for a small school project, not for a real
# production deployment.
VALID_TOKENS = set()


def load_staff_users():
    """
    Load the dict of staff accounts from staff_users.json.

    If the file doesn't exist yet (e.g. first time the app has ever
    run), create it with one default account: username "admin",
    password "changeme123". This default is public (it's written right
    here in the source code), so log in and add a real account — or at
    least check this one still has a safe password — right away.

    Returns:
        dict[str, str]: Maps username -> hashed password. Never maps to
        a plaintext password; only the hash is ever stored.
    """
    if not os.path.exists(STAFF_USERS_FILE):
        default_users = {"admin": generate_password_hash("changeme123")}
        save_staff_users(default_users)
        return default_users
    try:
        with open(STAFF_USERS_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_staff_users(users):
    """
    Write the full dict of staff accounts back to staff_users.json.

    Args:
        users (dict[str, str]): Maps username -> hashed password.
    """
    with open(STAFF_USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def login_required(view_func):
    """
    A decorator that blocks access to a route unless a valid staff
    token is included in the request.

    How to use it: put @login_required directly above a route function,
    below the @app.route(...) line.

    Expects the request to include a header like:
        Authorization: Bearer <token>
    where <token> was previously returned by POST /api/login.

    Returns:
        If the token is missing or invalid, immediately returns
        {"error": "Login required."} with status 401, without running
        the wrapped view function at all. If the token is valid, runs
        the wrapped view function normally.
    """
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()
        if not token or token not in VALID_TOKENS:
            return jsonify({"error": "Login required."}), 401
        return view_func(*args, **kwargs)
    return wrapper


def load_json_list(filepath):
    """
    Load a list of records from a JSON file on disk.

    Used for both contact_messages.json and enrolments.json — same
    shape, same failure handling, just a different file each time.

    Args:
        filepath (str): Path to the JSON file to read.

    Returns:
        list[dict]: All saved records, oldest first. Returns an empty
        list if the file doesn't exist yet, or is empty/corrupted.
    """
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        # If the file is empty or corrupted, don't crash the whole app —
        # just treat it as if there were no records yet.
        return []


def save_json_list(filepath, records):
    """
    Write a full list of records back to a JSON file, overwriting it.

    Args:
        filepath (str): Path to the JSON file to write.
        records (list[dict]): The complete list of records to save,
            including any new one just added.
    """
    with open(filepath, "w") as f:
        json.dump(records, f, indent=2)


def load_messages():
    """Load all previously saved contact messages. See load_json_list."""
    return load_json_list(MESSAGES_FILE)


def save_messages(messages):
    """Save the full list of contact messages. See save_json_list."""
    save_json_list(MESSAGES_FILE, messages)


def allowed_file(filename):
    """
    Check whether an uploaded file's extension is one we accept.

    LIMITATION: this only checks the filename's extension, not the
    file's actual content. Someone could rename any file type to end
    in ".pdf" and it would pass this check. A stronger version would
    inspect the file's actual bytes (its "magic number") instead of
    trusting the name. See KNOWN ISSUES #3 at the top of this file.

    Args:
        filename (str): The original filename from the upload, e.g.
            "report_card.pdf".

    Returns:
        bool: True if the file has one of the allowed extensions
        (pdf, jpg, jpeg, png), False otherwise (including if the
        filename has no extension at all).
    """
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def save_uploaded_file(file_storage):
    """
    Save an uploaded file to the uploads/ folder with a safe, unique name.

    Why a unique name: two different applicants might both upload a file
    called "report.pdf". Using the original name would let one overwrite
    the other. Prefixing with a random ID keeps every upload separate.

    Args:
        file_storage: A Flask/Werkzeug FileStorage object, as found on
            request.files["some_field_name"].

    Returns:
        str: The relative path (inside uploads/) where the file was
        saved, suitable for storing in the enrolment record.

    Raises:
        OSError: If the uploads/ folder can't be created or the file
            can't be written (e.g. disk full, permissions issue).
    """
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    original_name = secure_filename(file_storage.filename)
    unique_name = f"{uuid.uuid4().hex}_{original_name}"
    destination = os.path.join(UPLOAD_FOLDER, unique_name)
    file_storage.save(destination)
    return destination


@app.route("/api/contact", methods=["POST"])
def submit_contact():
    """
    Receive a contact form submission and save it.

    Expects a JSON body like:
        {
            "name": "Jane Doe",
            "email": "jane@example.com",
            "subject": "Enrolment question",
            "message": "Hi, I'd like to know..."
        }

    Validation rules:
        - All four fields are required and must be non-empty after
          trimming whitespace.
        - email must roughly look like an email address.

    Returns:
        On success (201): {"success": true}
        On validation failure (400): {"error": "<what went wrong>"}
        On unexpected server error (500): {"error": "..."}
    """
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "No data received. Please fill out the form."}), 400

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    subject = (data.get("subject") or "").strip()
    message = (data.get("message") or "").strip()

    # Check every field is present and non-empty.
    if not all([name, email, subject, message]):
        return jsonify({"error": "All fields are required."}), 400

    # Basic email shape check.
    if not EMAIL_PATTERN.match(email):
        return jsonify({"error": "Please enter a valid email address."}), 400

    new_entry = {
        "name": name,
        "email": email,
        "subject": subject,
        "message": message,
        "received_at": datetime.now().isoformat(),
    }

    try:
        messages = load_messages()
        messages.append(new_entry)
        save_messages(messages)
    except OSError:
        return jsonify({"error": "Could not save your message. Please try again."}), 500

    return jsonify({"success": True}), 201


@app.route("/api/contact", methods=["GET"])
@login_required
def list_contact_messages():
    """
    Return all saved contact messages. Requires a valid staff login
    token (see login_required and STAFF LOGIN in the module docstring).

    Returns:
        200: {"messages": [ ... ]}
        401: {"error": "Login required."} if not logged in
    """
    return jsonify({"messages": load_messages()}), 200


@app.route("/api/enrolment", methods=["POST"])
def submit_enrolment():
    """
    Receive a Grade 8 enrolment application and save it.

    Unlike the contact form, this endpoint expects a multipart/form-data
    submission (not JSON), because it includes two file uploads. The
    frontend sends this using the browser's FormData object.

    Expects form fields:
        - fullName (text, required)
        - ParentName (text, required)
        - PhoneNumber (text, required)
        - email (text, required, must look like an email)
    Expects files:
        - report (the applicant's latest school report; pdf/jpg/jpeg/png)
        - idCopy (a copy of the applicant's ID; pdf/jpg/jpeg/png)

    Validation rules:
        - All four text fields are required and must be non-empty after
          trimming whitespace.
        - email must roughly look like an email address.
        - Both files are required.
        - Both files must have an allowed extension (pdf, jpg, jpeg,
          png) — checked on the server, not just trusted from the
          browser's accept="" attribute.
        - Both files must be 5 MB or smaller.

    Returns:
        On success (201): {"success": true}
        On validation failure (400): {"error": "<what went wrong>"}
        On unexpected server error (500): {"error": "..."}

    Note:
        This endpoint does not yet require the applicant to log in, and
        does not yet email a confirmation. It also doesn't limit how
        many times the same person can submit. These would all be
        reasonable next improvements once the basic flow is working.
    """
    form = request.form
    files = request.files

    full_name = (form.get("fullName") or "").strip()
    parent_name = (form.get("ParentName") or "").strip()
    phone_number = (form.get("PhoneNumber") or "").strip()
    email = (form.get("email") or "").strip()

    if not all([full_name, parent_name, phone_number, email]):
        return jsonify({"error": "All fields are required."}), 400

    if not EMAIL_PATTERN.match(email):
        return jsonify({"error": "Please enter a valid parent/guardian email address."}), 400

    report_file = files.get("report")
    id_copy_file = files.get("idCopy")

    if not report_file or report_file.filename == "":
        return jsonify({"error": "Please upload the latest school report."}), 400

    if not id_copy_file or id_copy_file.filename == "":
        return jsonify({"error": "Please upload a copy of the student ID."}), 400

    for label, uploaded in (("school report", report_file), ("ID copy", id_copy_file)):
        if not allowed_file(uploaded.filename):
            return jsonify({
                "error": f"The {label} must be a PDF, JPG, or PNG file."
            }), 400

        # Check file size without loading the whole file into memory:
        # seek to the end to find its length, then seek back to the
        # start so it can still be saved normally afterwards.
        uploaded.seek(0, os.SEEK_END)
        size = uploaded.tell()
        uploaded.seek(0)
        if size > MAX_FILE_SIZE_BYTES:
            return jsonify({
                "error": f"The {label} is too large. Maximum size is 5 MB."
            }), 400

    try:
        # NOTE: these two saves happen one after another, not as a single
        # atomic step. If save_uploaded_file() succeeds for report_file
        # but then fails for id_copy_file, report_file is left saved on
        # disk with no matching enrolment record. See KNOWN ISSUES #1
        # at the top of this file.
        report_path = save_uploaded_file(report_file)
        id_copy_path = save_uploaded_file(id_copy_file)
    except OSError:
        return jsonify({"error": "Could not save your uploaded files. Please try again."}), 500

    new_entry = {
        "full_name": full_name,
        "parent_name": parent_name,
        "phone_number": phone_number,
        "email": email,
        "report_path": report_path,
        "id_copy_path": id_copy_path,
        "submitted_at": datetime.now().isoformat(),
    }

    try:
        # NOTE: read-modify-write on a shared file, not thread-safe.
        # Two submissions arriving at nearly the same time can both read
        # the file before either writes back, so one submission's data
        # can silently overwrite the other's. See KNOWN ISSUES #2 above.
        enrolments = load_json_list(ENROLMENTS_FILE)
        enrolments.append(new_entry)
        save_json_list(ENROLMENTS_FILE, enrolments)
    except OSError:
        return jsonify({"error": "Could not save your application. Please try again."}), 500

    return jsonify({"success": True}), 201


@app.route("/api/enrolment", methods=["GET"])
@login_required
def list_enrolments():
    """
    Return all saved enrolment applications. Requires a valid staff
    login token (see login_required and STAFF LOGIN in the module
    docstring). This data includes personal information about minors,
    which is exactly why it's protected.

    Returns:
        200: {"enrolments": [ ... ]}
        401: {"error": "Login required."} if not logged in
    """
    return jsonify({"enrolments": load_json_list(ENROLMENTS_FILE)}), 200


@app.route("/uploads/<path:filename>", methods=["GET"])
@login_required
def get_uploaded_file(filename):
    """
    Serve a previously uploaded file (a report card or ID copy) so it
    can be viewed or downloaded, e.g. from the staff dashboard. Requires
    a valid staff login token (see login_required).

    Args:
        filename (str): The unique filename saved by save_uploaded_file(),
            e.g. "959b4b04..._Nkosikhona_Mkhize.pdf". This is exactly
            the value stored in report_path/id_copy_path in
            enrolments.json (with the "uploads/" prefix stripped, since
            send_from_directory already knows the folder).

    Returns:
        The requested file (200), a 404 if it doesn't exist, or a 401
        if the request has no valid login token.
    """
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route("/api/login", methods=["POST"])
def login():
    """
    Check staff credentials and, if correct, issue a login token.

    Expects a JSON body like:
        {"username": "admin", "password": "changeme123"}

    Returns:
        On success (200): {"token": "<random token>"}
            Send this token in an "Authorization: Bearer <token>" header
            on every request to a protected route.
        On wrong username/password (401): {"error": "Invalid username or password."}
        On missing data (400): {"error": "Username and password are required."}

    Note:
        Deliberately gives the same error message whether the username
        or the password was wrong, rather than saying which one — this
        stops someone from using the error message to guess valid
        usernames one at a time.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    staff_users = load_staff_users()
    stored_hash = staff_users.get(username)

    if not stored_hash or not check_password_hash(stored_hash, password):
        return jsonify({"error": "Invalid username or password."}), 401

    token = secrets.token_hex(16)
    VALID_TOKENS.add(token)
    return jsonify({"token": token}), 200


@app.route("/api/logout", methods=["POST"])
def logout():
    """
    Invalidate a staff login token, logging that session out.

    Expects a JSON body like:
        {"token": "<the token to invalidate>"}

    Returns:
        200: {"success": true} whether or not the token was valid to
        begin with — logging out an already-invalid token isn't an
        error, since the end result (not being logged in) is the same.
    """
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    VALID_TOKENS.discard(token)
    return jsonify({"success": True}), 200


@app.route("/api/staff", methods=["GET"])
@login_required
def list_staff():
    """
    List existing staff usernames. Requires a valid login token.

    Only usernames are returned — never password hashes — since there's
    no reason the "Manage Staff" page needs to see those, even for
    staff who are already logged in.

    Returns:
        200: {"usernames": ["admin", "jsmith", ...]}
    """
    staff_users = load_staff_users()
    return jsonify({"usernames": sorted(staff_users.keys())}), 200


@app.route("/api/staff", methods=["POST"])
@login_required
def add_staff():
    """
    Create a new staff account. Requires a valid login token — only
    someone already logged in can create more staff accounts, which is
    what keeps this from being an open public sign-up form.

    Expects a JSON body like:
        {"username": "jsmith", "password": "a real password"}

    Validation rules:
        - Both fields required and non-empty after trimming.
        - Password must be at least 8 characters — a low bar, but
          better than allowing something like "1".
        - Username must not already exist.

    Returns:
        On success (201): {"success": true}
        On validation failure (400): {"error": "<what went wrong>"}
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    staff_users = load_staff_users()
    if username in staff_users:
        return jsonify({"error": "That username already exists."}), 400

    staff_users[username] = generate_password_hash(password)
    save_staff_users(staff_users)
    return jsonify({"success": True}), 201


@app.route("/api/staff/<username>", methods=["DELETE"])
@login_required
def delete_staff(username):
    """
    Remove a staff account. Requires a valid login token.

    Args:
        username (str): The account to remove, from the URL path.

    Validation rules:
        - The account must exist.
        - At least one staff account must always remain — deleting the
          last one would lock everyone out permanently, since there
          would be no way to log in and create a new one.

    Returns:
        On success (200): {"success": true}
        On validation failure (400): {"error": "<what went wrong>"}
    """
    staff_users = load_staff_users()

    if username not in staff_users:
        return jsonify({"error": "That account doesn't exist."}), 400

    if len(staff_users) <= 1:
        return jsonify({"error": "Can't delete the last remaining staff account."}), 400

    del staff_users[username]
    save_staff_users(staff_users)
    return jsonify({"success": True}), 200


if __name__ == "__main__":
    app.run(debug=True)
