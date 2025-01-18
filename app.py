from flask import Flask, render_template, request, redirect, url_for, flash, session
import psycopg2
from functools import wraps

app = Flask(__name__)
app.secret_key = "ovo_je_tajna_za_session"

DB_NAME = "projekt_db"
DB_USER = "postgres"
DB_PASS = "matija"
DB_HOST = "127.0.0.1"
DB_PORT = "5432"

def get_db_connection():
    return psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT
    )

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Morate biti prijavljeni za pristup.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'roles' not in session or ('ADMIN' not in session['roles']):
            flash("Samo administrator može pristupiti ovoj stranici.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def editor_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'roles' not in session:
            flash("Niste prijavljeni.", "danger")
            return redirect(url_for('index'))
        roles = session['roles']
        if ('ADMIN' not in roles) and ('EDITOR' not in roles):
            flash("Samo editor ili admin mogu ovo.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session and 'username' in session:
        return render_template('index.html', logged_in=True, username=session['username'])
    else:
        return render_template('index.html', logged_in=False)

@app.route('/login', methods=['GET','POST'])
def login():
    #Prijava korisnika - Blokiraj ako je user BANNED
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        cur = conn.cursor()
        # Dohvati usera po usernameu
        cur.execute("""
            SELECT user_id, password_hash, status
            FROM users
            WHERE username = %s
        """, (username,))
        user_row = cur.fetchone()

        if user_row is None:
            flash("Korisnik s tim imenom ne postoji.", "danger")
            cur.close()
            conn.close()
            return redirect(url_for('login'))

        user_id, db_hash, status = user_row

        # Ako je user BANNED, ne dopuštamo login
        if status == 'BANNED':
            flash("Vaš račun je blokiran (BANNED). Prijava nije moguća!", "danger")
            cur.close()
            conn.close()
            return redirect(url_for('login'))

        if db_hash == password:
            # Uspjeh -> postavi session
            session['user_id'] = user_id
            session['username'] = username
            # Dohvati uloge
            cur.execute("""
                SELECT r.role_name
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = %s
            """, (user_id,))
            roles = [row[0] for row in cur.fetchall()]
            session['roles'] = roles

            flash(f"Prijavljeni ste kao {username}.", "success")
        else:
            flash("Neispravna lozinka.", "danger")

        cur.close()
        conn.close()
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Odjavljeni ste.", "info")
    return redirect(url_for('index'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        status = 'ACTIVE'
        metadata = '{}'

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO users (username, password_hash, first_name, last_name, status, metadata)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING user_id
            """, (username, password, first_name, last_name, status, metadata))
            new_uid = cur.fetchone()[0]

            # Daj rolu VIEWER
            cur.execute("SELECT role_id FROM roles WHERE role_name = 'VIEWER'")
            row = cur.fetchone()
            if row:
                cur.execute("INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)", (new_uid, row[0]))

            conn.commit()
            flash("Uspješna registracija. Prijavite se.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Greška: {e}", "danger")
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/roles', methods=['GET','POST'])
@login_required
@admin_required
def roles():
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        role_name = request.form.get('role_name')
        description = request.form.get('description') or ''
        try:
            cur.execute("INSERT INTO roles (role_name, description) VALUES (%s, %s)", (role_name, description))
            conn.commit()
            flash("Nova uloga dodana!", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Greška: {e}", "danger")

    cur.execute("SELECT role_id, role_name, description FROM roles ORDER BY role_id;")
    all_roles = cur.fetchall()

    cur.close()
    conn.close()
    return render_template('roles.html', roles=all_roles)

@app.route('/users', methods=['GET','POST'])
@login_required
def users():
    roles = session.get('roles', [])
    current_user_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        if 'ADMIN' not in roles:
            flash("Samo admin može kreirati novog korisnika!", "danger")
        else:
            username = request.form.get('username')
            password_hash = request.form.get('password_hash')
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            status = request.form.get('status') or 'ACTIVE'
            metadata = request.form.get('metadata') or '{}'
            try:
                cur.execute("""
                    INSERT INTO users (username, password_hash, first_name, last_name, status, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (username, password_hash, first_name, last_name, status, metadata))
                conn.commit()
                flash("Novi korisnik uspješno dodan!", "success")
            except Exception as e:
                conn.rollback()
                flash(f"Greška pri kreiranju korisnika: {e}", "danger")

    if 'ADMIN' in roles or 'EDITOR' in roles:
        # admin/editor -> svi useri
        cur.execute("""
            SELECT user_id, username, first_name, last_name, status, last_modified
            FROM users
            ORDER BY user_id
        """)
    else:
        # viewer -> samo sebe
        cur.execute("""
            SELECT user_id, username, first_name, last_name, status, last_modified
            FROM users
            WHERE user_id = %s
        """, (current_user_id,))

    all_users = cur.fetchall()

    cur.close()
    conn.close()
    return render_template('users.html', users=all_users)

@app.route('/user/<int:user_id>', methods=['GET','POST'])
@login_required
@admin_required
def user_detail(user_id):
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        # Ažuriranje
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        status = request.form.get('status')
        metadata = request.form.get('metadata') or '{}'

        try:
            cur.execute("""
                UPDATE users
                SET first_name = %s,
                    last_name = %s,
                    status = %s,
                    metadata = %s
                WHERE user_id = %s
            """, (first_name, last_name, status, metadata, user_id))
        except Exception as e:
            conn.rollback()
            flash(f"Greška pri ažuriranju korisnika: {e}", "danger")
        else:
            # Ažuriranje uloga
            selected_roles = request.form.getlist('roles')
            try:
                # obriši stare
                cur.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
                # dodaj nove
                for role_name in selected_roles:
                    cur.execute("""
                        INSERT INTO user_roles (user_id, role_id)
                        SELECT %s, role_id FROM roles WHERE role_name = %s
                    """, (user_id, role_name))
                conn.commit()
                flash("Korisnik uspješno ažuriran!", "success")
            except Exception as e:
                conn.rollback()
                flash(f"Greška pri ažuriranju uloga: {e}", "danger")

    # Dohvati podatke o korisniku
    cur.execute("""
        SELECT user_id, username, first_name, last_name, status, metadata
        FROM users
        WHERE user_id = %s
    """, (user_id,))
    user = cur.fetchone()

    # Dohvati sve role
    cur.execute("SELECT role_name FROM roles ORDER BY role_id")
    available_roles = [row[0] for row in cur.fetchall()]

    cur.execute("""
        SELECT r.role_name
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.role_id
        WHERE ur.user_id = %s
    """, (user_id,))
    current_roles = [row[0] for row in cur.fetchall()]

    cur.close()
    conn.close()

    return render_template('user_detail.html',
                           user=user,
                           available_roles=available_roles,
                           current_roles=current_roles)

@app.route('/orders', methods=['GET','POST'])
@login_required
def orders():
    conn = get_db_connection()
    cur = conn.cursor()
    user_id = session['user_id']
    roles = session.get('roles', [])

    # Kreiranje narudžbe
    if request.method == 'POST':
        total_price = request.form.get('total_price') or "0"
        try:
            cur.execute("""
                INSERT INTO orders (user_id, total_price, status_id)
                VALUES (%s, %s, NULL)
            """, (user_id, total_price))
            conn.commit()
            flash("Narudžba je uspješno kreirana.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Greška pri kreiranju narudžbe: {e}", "danger")

    # Dohvat narudžbi
    if 'ADMIN' or 'EDITOR' in roles:
        # Admin i editor -> sve narudžbe
        cur.execute("""
            SELECT o.order_id, u.username, o.order_date, o.total_price, s.name as status
            FROM orders o
            JOIN users u ON o.user_id = u.user_id
            JOIN order_statuses s ON s.status_id = o.status_id
            ORDER BY o.order_id
        """)
    else:
        # Ostali -> samo vlastite
        cur.execute("""
            SELECT o.order_id, u.username, o.order_date, o.total_price, s.name as status
            FROM orders o
            JOIN users u ON o.user_id = u.user_id
            JOIN order_statuses s ON s.status_id = o.status_id
            WHERE o.user_id = %s
            ORDER BY o.order_id
        """, (user_id,))

    all_orders = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('orders.html', orders=all_orders)

@app.route('/update_order_status', methods=['POST'])
@login_required
@editor_or_admin_required
def update_order_status():
    order_id = request.form.get('order_id')
    new_status = request.form.get('new_status')

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT status_id FROM order_statuses WHERE name = %s", (new_status,))
    row = cur.fetchone()
    if not row:
        flash("Neispravan status!", "danger")
        return redirect(url_for('orders'))
    new_status_id = row[0]

    try:
        cur.execute("UPDATE orders SET status_id=%s WHERE order_id=%s", (new_status_id, order_id))
        if cur.rowcount == 0:
            flash("Takva narudžba ne postoji.", "warning")
        else:
            flash("Status narudžbe ažuriran!", "success")
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Greška pri ažuriranju statusa: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('orders'))

@app.route('/ban_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def ban_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE users
            SET status = 'BANNED'
            WHERE user_id = %s
        """, (user_id,))
        if cur.rowcount > 0:
            flash("Korisnik je postao BANNED, aktivne narudžbe otkazane.", "success")
        else:
            flash("Nepostojeći korisnik.", "warning")
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Greška pri banu korisnika: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('users'))

@app.route('/unban_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def unban_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE users
            SET status = 'ACTIVE'
            WHERE user_id = %s
        """, (user_id,))
        if cur.rowcount > 0:
            flash("Korisnik je deblokiran (ACTIVE).", "success")
        else:
            flash("Nepostojeći korisnik.", "warning")
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Greška pri unban korisnika: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('users'))

@app.route('/make_vip/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def make_vip(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE users
            SET metadata = jsonb_set(metadata, '{vip}', '"true"', true)
            WHERE user_id = %s
        """, (user_id,))
        if cur.rowcount > 0:
            flash("Korisnik sada ima VIP status (10% popusta na buduće narudžbe).", "success")
        else:
            flash("Nepostojeći korisnik.", "warning")
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Greška pri postavljanju VIP statusa: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('users'))

@app.route('/remove_vip/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def remove_vip(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE users
            SET metadata = metadata - 'vip'
            WHERE user_id = %s
        """, (user_id,))
        if cur.rowcount > 0:
            flash("VIP status uklonjen.", "success")
        else:
            flash("Nepostojeći korisnik.", "warning")
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Greška pri uklanjanju VIP statusa: {e}", "danger")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('users'))
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    current_user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        metadata = request.form.get('metadata') or '{}'
        try:
            cur.execute("""
                UPDATE users
                SET first_name=%s, last_name=%s, metadata=%s
                WHERE user_id=%s
            """, (first_name, last_name, metadata, current_user_id))
            conn.commit()
            flash("Profil ažuriran!", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Greška pri ažuriranju profila: {e}", "danger")

    cur.execute("""
        SELECT user_id, username, first_name, last_name, status, metadata
        FROM users
        WHERE user_id=%s
    """, (current_user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return render_template('profile.html', user=user)

@app.route('/audit')
@login_required
def audit_log():
    roles = session.get('roles', [])
    if 'ADMIN' not in roles:
        flash("Samo administrator može vidjeti Audit Log!", "danger")
        return redirect(url_for('index'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT log_id, table_name, operation, changed_by, changed_at, old_data, new_data
            FROM audit_log
            ORDER BY changed_at DESC
            LIMIT 100
        """)
        logs = cur.fetchall()
    except Exception as e:
        logs = []
        flash(f"Greška pri dohvaćanju audit loga: {e}", "danger")
    finally:
        cur.close()
        conn.close()

    return render_template('audit.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
