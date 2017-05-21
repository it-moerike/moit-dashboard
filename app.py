from flask import Flask
from flask import render_template, flash, request, redirect, url_for, session

from passlib.hash import pbkdf2_sha512
from functools import wraps
import datetime
import paramiko

from bson.objectid import ObjectId

from dbconnect import connection
import config

app = Flask(__name__)
app.secret_key = config.secret_key

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Du musst dich anmelden!")
            return redirect(url_for("index"))
    return wrap


def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "admin" in session:
            return f(*args, **kwargs)
        else:
            flash("Du bist kein admin!")
            return redirect(url_for("index"))
    return wrap


@app.route("/", methods=["GET", "POST"])
def index():
    error = None

    # If user is logged in, redirect him to dashboard
    if "logged_in" in session:
            return redirect(url_for("dashboard"))

    try:
        client, db = connection()

        if request.method == "POST":

            # Get form values
            attempted_username = request.form["username"].lower()
            attempted_password = request.form["password"]

            data = db.users.find_one({"username": attempted_username})

            if data:
                # Get data from db
                database_password = data["password"]
                uid = str(data["_id"])
                username = data["username"]
                rank = data["rank"]

                # If no password has been set
                if database_password == False:
                    password_hashed = pbkdf2_sha512.hash(attempted_password)
                    db.users.update({"_id": ObjectId(uid)},
                                    {"$set": {
                                        "password": password_hashed
                                    }})
                    flash("Dein Passwort wurde erfolgreich gesetzt! Melde dich bitte erneut an!")
                    return redirect(url_for("index"))

                # Check hash
                if pbkdf2_sha512.verify(attempted_password, database_password):
                    flash("Hallo, " + username + " Du hast dich erfolgreich angemeldet!")
                    session["logged_in"] = True
                    session["username"] = username
                    session["uid"] = uid

                    # Check admin
                    if rank == "admin":
                        session["admin"] = True
                        flash("Du bist ein Admin!")
                        return redirect(url_for("admin"))

                    return redirect(url_for("dashboard"))

                # Wrong username or password
                else:
                    error = "Falscher Benutzername oder falsches Passwort!"

    except Exception as e:
        error = e

    return render_template("index.html", error=error, title="Login")


@app.route("/logout")
@login_required
def logout():
    # Delete all variables from user session
    session.clear()
    flash("You logged out successfully!")
    return redirect(url_for("index"))


###
# DASHBOARD
###

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    error = None
    client, db = connection()
    domains = [domain for domain in db.domains.find({"uid": str(session["uid"])})]

    # User wants to create a new domain
    if request.method == "POST":
        # Get form value
        domainname = request.form["domainname"]

        # Check for special characters
        characters = [".", ",", "-", "/", ":", ";", "_", "!", "=", "?", "*", "#", "+", "~", "ä", "ö", "ü"]
        for character in characters:
            if character in domainname:
                error = "Verwende keine Sonderzeichen in deinem Domainname!"
                return render_template("dashboard.html", title="Dashboard", error=error, domains=domains)
            else:
                pass

        # Check whether domainname is already taken
        check_domain = db.domains.find_one({"name": domainname})
        print(check_domain)
        if check_domain:
            error = "Diese Domain gibst es schon! Wähle eine andere."
            return render_template("dashboard.html", title="Dashboard", error=error, domains=domains)

        # Insert it in the database
        domain = {
            "name": domainname,
            "registration_date": datetime.datetime.now().strftime("%Y-%m-%d"),
            "uid": str(session["uid"]),
            "activated": False
        }
        db.domains.insert_one(domain)

        # Get the domains again, so the new domain is in the list
        domains = [domain for domain in db.domains.find({"uid": str(session["uid"])})]

        flash("Deine Domain " + domainname + ".moit.ml wird erstellt. Nun musst Du einige Zeit warten, bis deine Domain online ist!")


    return render_template("dashboard.html", title="Dashboard", error=error, domains=domains)


@app.route("/dashboard/folder/<string:domainname>")
@app.route("/dashboard/folder/<string:domainname>/<path:path>")
@login_required
def dashboardFolder(domainname, path=None):
    client, db = connection()

    domain = db.domains.find_one({"name": domainname, "uid": str(session["uid"])})
    # TODO: Check whether it's activated
    
    # If domain doesn't exist or user has no permission
    if not domain:
        flash("Du hast keine Berechtigung, diese Domain zu bearbeiten!")
        return redirect(url_for("dashboard"))

    # Connect to FTP-Server
    transport = paramiko.Transport((config.ftp_host, config.ftp_port))
    transport.connect(username=config.ftp_username, password=config.ftp_password)

    ok = False
    while not ok:
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.chdir("public_html/" + domainname)
            foldercontent = sftp.listdir_attr()
            pwd = sftp.getcwd()
            ok = True
        except Exception as e:
            print(e)

    # Create filelist
    files = list()
    for i in foldercontent:
        i = str(i)

        # Get type (directory or file)
        if i[0] == "d":
            filetype = "d"
        else:
            filetype = "f"

        splittedFile = i.split(" ")

        # Don't show hidden files
        if splittedFile[-1][0] != ".":
            # Append dict ("filename": "file.py", "type": "f") to list
            files.append({"filename": splittedFile[-1], "filetype": filetype})

    # TODO: Order files

    return render_template("dashboard-folder.html", title="Config " + domainname, domainname=domainname, files=files, pwd=pwd)


###
# ADMIN
###


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    error = None
    client, db = connection()

    # Get all infos from db
    not_activated_domains = [domain for domain in db.domains.find({"activated": False})]
    domains = [domain for domain in db.domains.find({"activated": {"$ne": False}})]
    users = [user for user in db.users.find()]

    # Add username to list
    for domain in not_activated_domains:
        uid = domain["uid"]
        username = db.users.find_one({"_id": ObjectId(uid)})
        domain["username"] = username["username"]
    for domain in domains:
        uid = domain["uid"]
        username = db.users.find_one({"_id": ObjectId(uid)})
        domain["username"] = username["username"]

    # Create new user
    if request.method == "POST":
        username = request.form["username"].lower()
        user = {
            "username": username,
            "password": False,
            "rank": "user",
            "registration_date": datetime.datetime.now().strftime("%Y-%m-%d")
        }
        db.users.insert_one(user)

        flash("User " + username + " wurde hinzugefügt!")

        # Redirect to this page, so new user will be in list
        return redirect(url_for("admin"))

    return render_template("admin.html", title="Admin", error=error, users=users,
                           not_activated_domains=not_activated_domains, domains=domains)


@admin_required
@app.route("/admin/done/<string:domainname>")
def adminDone(domainname):
    client, db = connection()
    # Set a domainname as created
    db.domains.update({"name": domainname},
                      {"$set": {
                          "activated": session["username"]
                      }})

    flash("Domain " + domainname + ".moit.ml wurde als aktiviert festgelegt.")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(debug=True)
