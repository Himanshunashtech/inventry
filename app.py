from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from flask import Response
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
import io

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
DATABASE = 'inventory.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db_connection()
        with open('schema.sql', 'r') as f:
            conn.executescript(f.read())
        conn.commit()
        conn.close()

# Authentication decorators
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') not in ['superadmin', 'admin']:
            flash('Access denied. Admin privileges required.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'superadmin':
            flash('Access denied. Super admin privileges required.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/inventory/download-pdf')
@login_required
def download_inventory_pdf():
    # Get inventory data
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM inventory ORDER BY name').fetchall()
    conn.close()
    
    # Create PDF in memory
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    
    # Create styles
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = styles['Heading1']
    title_style.alignment = 1  # Center alignment
    title = Paragraph("Inventory Report", title_style)
    story.append(title)
    story.append(Spacer(1, 0.2*inch))
    
    # Report info
    info_style = styles['Normal']
    info_style.alignment = 1
    report_date = Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style)
    story.append(report_date)
    story.append(Spacer(1, 0.3*inch))
    
    # Prepare table data
    table_data = [['Name', 'Category', 'Quantity', 'Price', 'Last Updated']]
    
    for item in items:
        table_data.append([
            item['name'],
            item['category'] or 'N/A',
            str(item['quantity']),
            f"${item['price']:.2f}",
            item['updated_at'][:16] if item['updated_at'] else 'N/A'
        ])
    
    # Create table
    table = Table(table_data, colWidths=[2*inch, 1.5*inch, 1*inch, 1*inch, 1.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(table)
    
    # Summary
    story.append(Spacer(1, 0.3*inch))
    total_items = len(items)
    total_value = sum(item['quantity'] * item['price'] for item in items)
    low_stock = sum(1 for item in items if item['quantity'] < 10)
    
    summary_text = f"""
    <b>Summary:</b><br/>
    Total Items: {total_items}<br/>
    Total Inventory Value: ${total_value:.2f}<br/>
    Low Stock Items (less than 10): {low_stock}
    """
    summary = Paragraph(summary_text, styles['Normal'])
    story.append(summary)
    
    # Build PDF
    doc.build(story)
    
    # Prepare response
    buffer.seek(0)
    filename = f"inventory_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return Response(
        buffer,
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename={filename}',
            'Content-Type': 'application/pdf'
        }
    )

# Alternative simple PDF version (if you have issues with the above)
@app.route('/inventory/download-simple-pdf')
@login_required
def download_inventory_simple_pdf():
    # Get inventory data
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM inventory ORDER BY name').fetchall()
    conn.close()
    
    # Create simple PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph("Inventory Report", styles['Heading1'])
    story.append(title)
    story.append(Spacer(1, 12))
    
    # Table data
    data = [['Name', 'Qty', 'Price', 'Category']]
    for item in items:
        data.append([
            item['name'],
            str(item['quantity']),
            f"${item['price']:.2f}",
            item['category'] or 'N/A'
        ])
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(table)
    doc.build(story)
    
    buffer.seek(0)
    return Response(
        buffer.getvalue(),
        mimetype='application/pdf',
        headers={'Content-Disposition': 'attachment; filename=inventory.pdf'}
    )




@app.route('/')
def index():
    return redirect(url_for('login'))

# REMOVED: Public registration route

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username']  # This field can be username OR email
        password = request.form['password']
        
        print(f"DEBUG: Login attempt - username/email: '{username_or_email}', password: '{password}'")
        
        conn = get_db_connection()
        # Search by both username AND email
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?', 
            (username_or_email, username_or_email)
        ).fetchone()
        conn.close()
        
        if user:
            print(f"DEBUG: Found user - username: '{user['username']}', email: '{user['email']}', role: '{user['role']}'")
            
            # Use proper password hash checking
            if check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                flash(f'Welcome back, {user["username"]}!')
                return redirect(url_for('dashboard'))
            else:
                print("DEBUG: Password doesn't match")
        else:
            print("DEBUG: User not found")
        
        flash('Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    
    # Get inventory stats
    total_items = conn.execute('SELECT COUNT(*) FROM inventory').fetchone()[0]
    low_stock = conn.execute('SELECT COUNT(*) FROM inventory WHERE quantity < 10').fetchone()[0]
    
    # Only show user count to admins and superadmins
    total_users = 0
    if session['role'] in ['superadmin', 'admin']:
        total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    
    # Get recent inventory
    recent_items = conn.execute(
        'SELECT * FROM inventory ORDER BY created_at DESC LIMIT 5'
    ).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         total_items=total_items, 
                         low_stock=low_stock,
                         total_users=total_users,
                         recent_items=recent_items)

# Inventory Management Routes
@app.route('/inventory')
@login_required
def inventory():
    search = request.args.get('search', '')
    conn = get_db_connection()
    
    if search:
        items = conn.execute(
            'SELECT * FROM inventory WHERE name LIKE ? OR description LIKE ? OR category LIKE ?',
            (f'%{search}%', f'%{search}%', f'%{search}%')
        ).fetchall()
    else:
        items = conn.execute('SELECT * FROM inventory').fetchall()
    
    conn.close()
    return render_template('inventory.html', items=items, search=search)

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_inventory():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        quantity = request.form['quantity']
        price = request.form['price']
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO inventory (name, description, category, quantity, price, created_by) VALUES (?, ?, ?, ?, ?, ?)',
            (name, description, category, quantity, price, session['user_id'])
        )
        conn.commit()
        conn.close()
        
        flash('Inventory item added successfully!')
        return redirect(url_for('inventory'))
    
    return render_template('add_inventory.html')

@app.route('/inventory/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_inventory(id):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM inventory WHERE id = ?', (id,)).fetchone()
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        quantity = request.form['quantity']
        price = request.form['price']
        
        conn.execute(
            'UPDATE inventory SET name = ?, description = ?, category = ?, quantity = ?, price = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            (name, description, category, quantity, price, id)
        )
        conn.commit()
        conn.close()
        
        flash('Inventory item updated successfully!')
        return redirect(url_for('inventory'))
    
    conn.close()
    return render_template('edit_inventory.html', item=item)

@app.route('/inventory/delete/<int:id>')
@login_required
def delete_inventory(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM inventory WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash('Inventory item deleted successfully!')
    return redirect(url_for('inventory'))

# User Management Routes (Only superadmin can create users)
@app.route('/users')
@login_required
def users():
    search = request.args.get('search', '')
    conn = get_db_connection()
    
    # Regular users can only see their own profile
    if session['role'] == 'user':
        users_list = conn.execute(
            'SELECT * FROM users WHERE id = ?', (session['user_id'],)
        ).fetchall()
    # Admins and superadmins can see all users
    else:
        if search:
            users_list = conn.execute(
                'SELECT * FROM users WHERE username LIKE ? OR email LIKE ?',
                (f'%{search}%', f'%{search}%')
            ).fetchall()
        else:
            users_list = conn.execute('SELECT * FROM users').fetchall()
    
    conn.close()
    return render_template('users.html', users=users_list, search=search)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
@superadmin_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']
        
        conn = get_db_connection()
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?', 
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('Username or email already exists')
            return render_template('add_user.html')
        
        hashed_password = generate_password_hash(password)
        conn.execute(
            'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
            (username, hashed_password, email, role)
        )
        conn.commit()
        conn.close()
        
        flash(f'User {username} added successfully! Password: {password}')
        return redirect(url_for('users'))
    
    return render_template('add_user.html')

@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@superadmin_required
def edit_user(id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        
        # Check if username/email already exists (excluding current user)
        existing_user = conn.execute(
            'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?', 
            (username, email, id)
        ).fetchone()
        
        if existing_user:
            flash('Username or email already exists')
            return render_template('edit_user.html', user=user)
        
        conn.execute(
            'UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?',
            (username, email, role, id)
        )
        conn.commit()
        flash('User updated successfully!')
        return redirect(url_for('users'))
    
    conn.close()
    return render_template('edit_user.html', user=user)

@app.route('/users/delete/<int:id>')
@login_required
@superadmin_required
def delete_user(id):
    if id == session['user_id']:
        flash('You cannot delete your own account!')
        return redirect(url_for('users'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully!')
    return redirect(url_for('users'))

# Profile Management
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect')
        elif new_password != confirm_password:
            flash('New passwords do not match')
        else:
            hashed_password = generate_password_hash(new_password)
            conn.execute(
                'UPDATE users SET password = ? WHERE id = ?',
                (hashed_password, session['user_id'])
            )
            conn.commit()
            flash('Password updated successfully!')
        
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    conn.close()
    return render_template('profile.html', user=user)

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)