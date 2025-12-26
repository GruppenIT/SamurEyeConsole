import os
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from models import db, User, Contract, Appliance, Metric, LoginLog, ThreatMetadata

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'samureye-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', ping_timeout=120, ping_interval=25)

connected_appliances = {}
shell_sessions = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

BRAZIL_OFFSET = timedelta(hours=-3)

@app.template_filter('to_brazil_tz')
def to_brazil_tz(dt):
    if dt is None:
        return ''
    return dt + BRAZIL_OFFSET

@app.context_processor
def utility_processor():
    return {'now': datetime.utcnow}

def init_db():
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(email='admin@samureye.com.br').first()
        admin_password = os.environ.get('ADMIN_PASSWORD')
        if not admin:
            if not admin_password:
                import secrets
                admin_password = secrets.token_urlsafe(16)
                print(f"\n{'='*60}")
                print("FIRST RUN: Admin account created")
                print(f"Email: admin@samureye.com.br")
                print(f"Generated Password: {admin_password}")
                print("IMPORTANT: Set ADMIN_PASSWORD env var in production!")
                print(f"{'='*60}\n")
            admin = User(email='admin@samureye.com.br')
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
        elif admin_password:
            admin.set_password(admin_password)
            db.session.commit()
            print("Admin password updated from ADMIN_PASSWORD environment variable")

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Email ou senha invalidos', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

PERIOD_OPTIONS = {
    '1h': {'hours': 1, 'label': 'Ultima hora'},
    '6h': {'hours': 6, 'label': 'Ultimas 6 horas'},
    '24h': {'hours': 24, 'label': 'Ultimas 24 horas'},
    '7d': {'hours': 168, 'label': 'Ultimos 7 dias'},
    '30d': {'hours': 720, 'label': 'Ultimos 30 dias'},
    '90d': {'hours': 2160, 'label': 'Ultimos 90 dias'}
}

DATA_RETENTION_DAYS = 90

@app.route('/dashboard')
@login_required
def dashboard():
    period = request.args.get('period', '24h')
    if period not in PERIOD_OPTIONS:
        period = '24h'
    
    hours = PERIOD_OPTIONS[period]['hours']
    since = datetime.utcnow() - timedelta(hours=hours)
    max_points = hours * 12 + 100
    
    contracts = Contract.query.all()
    total_appliances = Appliance.query.count()
    active_appliances = Appliance.query.filter(
        Appliance.last_seen >= datetime.utcnow() - timedelta(minutes=10)
    ).count()
    
    recent_metrics = Metric.query.filter(
        Metric.timestamp >= since
    ).order_by(Metric.timestamp.desc()).limit(max_points).all()
    
    return render_template('dashboard.html', 
                         contracts=contracts,
                         total_appliances=total_appliances,
                         active_appliances=active_appliances,
                         recent_metrics=list(reversed(recent_metrics)),
                         current_period=period,
                         period_options=PERIOD_OPTIONS)

@app.route('/contracts')
@login_required
def contracts():
    contracts = Contract.query.order_by(Contract.created_at.desc()).all()
    return render_template('contracts.html', contracts=contracts)

@app.route('/contracts/new', methods=['GET', 'POST'])
@login_required
def new_contract():
    if request.method == 'POST':
        contract = Contract(
            client_name=request.form['client_name'],
            contact_email=request.form['contact_email'],
            start_date=datetime.strptime(request.form['start_date'], '%Y-%m-%d').date(),
            end_date=datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        )
        db.session.add(contract)
        db.session.commit()
        flash('Contrato criado com sucesso!', 'success')
        return redirect(url_for('contracts'))
    return render_template('contract_form.html', contract=None)

@app.route('/contracts/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_contract(id):
    contract = Contract.query.get_or_404(id)
    if request.method == 'POST':
        contract.client_name = request.form['client_name']
        contract.contact_email = request.form['contact_email']
        contract.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        contract.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()
        contract.is_active = 'is_active' in request.form
        db.session.commit()
        flash('Contrato atualizado!', 'success')
        return redirect(url_for('contracts'))
    return render_template('contract_form.html', contract=contract)

@app.route('/contracts/<int:id>/delete', methods=['POST'])
@login_required
def delete_contract(id):
    contract = Contract.query.get_or_404(id)
    db.session.delete(contract)
    db.session.commit()
    flash('Contrato removido!', 'success')
    return redirect(url_for('contracts'))

@app.route('/contracts/<int:id>')
@login_required
def view_contract(id):
    contract = Contract.query.get_or_404(id)
    return render_template('contract_view.html', contract=contract)

@app.route('/contracts/<int:contract_id>/appliances/new', methods=['GET', 'POST'])
@login_required
def new_appliance(contract_id):
    contract = Contract.query.get_or_404(contract_id)
    if request.method == 'POST':
        appliance = Appliance(
            contract_id=contract_id,
            name=request.form['name'],
            description=request.form.get('description', ''),
            token=Appliance.generate_token()
        )
        db.session.add(appliance)
        db.session.commit()
        flash(f'Appliance criado! Token: {appliance.token}', 'success')
        return redirect(url_for('view_contract', id=contract_id))
    return render_template('appliance_form.html', contract=contract, appliance=None)

@app.route('/appliances/<int:id>')
@login_required
def view_appliance(id):
    period = request.args.get('period', '24h')
    if period not in PERIOD_OPTIONS:
        period = '24h'
    
    hours = PERIOD_OPTIONS[period]['hours']
    since = datetime.utcnow() - timedelta(hours=hours)
    max_points = hours * 12 + 100
    
    appliance = Appliance.query.get_or_404(id)
    metrics = appliance.metrics.filter(Metric.timestamp >= since).order_by(Metric.timestamp.desc()).limit(max_points).all()
    login_logs = appliance.login_logs.filter(
        LoginLog.timestamp >= since,
        LoginLog.source_ip.notin_(['127.0.0.1', '::1', 'localhost'])
    ).order_by(LoginLog.timestamp.desc()).all()
    threats = appliance.threat_metadata.filter(ThreatMetadata.timestamp >= since).order_by(ThreatMetadata.timestamp.desc()).all()
    is_tunnel_connected = appliance.token in connected_appliances
    return render_template('appliance_view.html', 
                         appliance=appliance, 
                         metrics=list(reversed(metrics)),
                         login_logs=login_logs,
                         threats=threats,
                         is_tunnel_connected=is_tunnel_connected,
                         current_period=period,
                         period_options=PERIOD_OPTIONS)

@app.route('/appliances/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_appliance(id):
    appliance = Appliance.query.get_or_404(id)
    if request.method == 'POST':
        appliance.name = request.form['name']
        appliance.description = request.form.get('description', '')
        appliance.is_active = 'is_active' in request.form
        db.session.commit()
        flash('Appliance atualizado!', 'success')
        return redirect(url_for('view_appliance', id=id))
    return render_template('appliance_form.html', contract=appliance.contract, appliance=appliance)

@app.route('/appliances/<int:id>/reset-token', methods=['POST'])
@login_required
def reset_appliance_token(id):
    appliance = Appliance.query.get_or_404(id)
    new_token = appliance.reset_token()
    db.session.commit()
    flash(f'Token resetado! Novo token: {new_token}', 'success')
    return redirect(url_for('view_appliance', id=id))

@app.route('/appliances/<int:id>/delete', methods=['POST'])
@login_required
def delete_appliance(id):
    appliance = Appliance.query.get_or_404(id)
    contract_id = appliance.contract_id
    db.session.delete(appliance)
    db.session.commit()
    flash('Appliance removido!', 'success')
    return redirect(url_for('view_contract', id=contract_id))

@app.route('/api/v1/appliances/<int:id>/tunnel-status')
@login_required
def get_tunnel_status(id):
    appliance = Appliance.query.get_or_404(id)
    return jsonify({
        'connected': appliance.token in connected_appliances,
        'appliance_id': id
    })

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Appliance-Token')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        appliance = Appliance.query.filter_by(token=token, is_active=True).first()
        if not appliance:
            return jsonify({'error': 'Invalid or inactive token'}), 401
        if not appliance.contract.is_valid:
            return jsonify({'error': 'Contract expired or inactive'}), 403
        request.appliance = appliance
        return f(*args, **kwargs)
    return decorated

@app.route('/api/v1/telemetry/metrics', methods=['POST'])
@require_token
def receive_metrics():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    metric = Metric(
        appliance_id=request.appliance.id,
        cpu_percent=data.get('cpu_percent'),
        memory_percent=data.get('memory_percent'),
        memory_used_gb=data.get('memory_used_gb'),
        memory_total_gb=data.get('memory_total_gb'),
        disk_percent=data.get('disk_percent'),
        disk_used_gb=data.get('disk_used_gb'),
        disk_total_gb=data.get('disk_total_gb'),
        network_bytes_sent=data.get('network_bytes_sent'),
        network_bytes_recv=data.get('network_bytes_recv'),
        network_bytes_sent_rate=data.get('network_bytes_sent_rate'),
        network_bytes_recv_rate=data.get('network_bytes_recv_rate')
    )
    request.appliance.last_seen = datetime.utcnow()
    db.session.add(metric)
    db.session.commit()
    return jsonify({'status': 'ok', 'metric_id': metric.id})

@app.route('/api/v1/telemetry/login-logs', methods=['POST'])
@require_token
def receive_login_logs():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    logs = data if isinstance(data, list) else [data]
    for log_data in logs:
        log = LoginLog(
            appliance_id=request.appliance.id,
            login_type=log_data.get('login_type', 'SSH'),
            username=log_data.get('username'),
            source_ip=log_data.get('source_ip'),
            success=log_data.get('success', True),
            details=log_data.get('details')
        )
        db.session.add(log)
    request.appliance.last_seen = datetime.utcnow()
    db.session.commit()
    return jsonify({'status': 'ok', 'count': len(logs)})

@app.route('/api/v1/telemetry/threats', methods=['POST'])
@require_token
def receive_threats():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    threats = data if isinstance(data, list) else [data]
    for threat_data in threats:
        threat = ThreatMetadata(
            appliance_id=request.appliance.id,
            threat_type=threat_data.get('threat_type'),
            severity=threat_data.get('severity'),
            source_ip=threat_data.get('source_ip'),
            destination_ip=threat_data.get('destination_ip'),
            count=threat_data.get('count', 1),
            metadata_json=str(threat_data.get('metadata', {}))
        )
        db.session.add(threat)
    request.appliance.last_seen = datetime.utcnow()
    db.session.commit()
    return jsonify({'status': 'ok', 'count': len(threats)})

@app.route('/api/v1/license/validate', methods=['GET'])
@require_token
def validate_license():
    contract = request.appliance.contract
    return jsonify({
        'valid': contract.is_valid,
        'appliance_name': request.appliance.name,
        'client_name': contract.client_name,
        'contract_start': contract.start_date.isoformat(),
        'contract_end': contract.end_date.isoformat(),
        'is_active': contract.is_active,
        'validated_at': datetime.utcnow().isoformat()
    })


@socketio.on('connect', namespace='/appliance')
def appliance_connect(auth):
    token = auth.get('token') if auth else None
    if not token:
        token = request.args.get('token')
    if not token:
        print("[TUNNEL] Connection rejected: no token provided")
        return False
    
    with app.app_context():
        appliance = Appliance.query.filter_by(token=token, is_active=True).first()
        if not appliance or not appliance.contract.is_valid:
            print(f"[TUNNEL] Connection rejected: invalid token {token[:8]}...")
            return False
        
        connected_appliances[token] = {
            'sid': request.sid,
            'appliance_id': appliance.id,
            'appliance_name': appliance.name,
            'connected_at': datetime.utcnow()
        }
        join_room(f'appliance_{token}')
        print(f"[TUNNEL] Appliance connected: {appliance.name} (token: {token[:8]}...)")
        return True

@socketio.on('disconnect', namespace='/appliance')
def appliance_disconnect():
    token_to_remove = None
    for token, info in connected_appliances.items():
        if info['sid'] == request.sid:
            token_to_remove = token
            break
    
    if token_to_remove:
        info = connected_appliances.pop(token_to_remove)
        print(f"[TUNNEL] Appliance disconnected: {info['appliance_name']}")
        if token_to_remove in shell_sessions:
            del shell_sessions[token_to_remove]

@socketio.on('shell_output', namespace='/appliance')
def handle_shell_output(data):
    token = None
    for t, info in connected_appliances.items():
        if info['sid'] == request.sid:
            token = t
            break
    
    if token and token in shell_sessions:
        console_sid = shell_sessions[token].get('console_sid')
        if console_sid:
            socketio.emit('shell_output', {'output': data.get('output', '')}, 
                         room=console_sid, namespace='/console')

@socketio.on('shell_closed', namespace='/appliance')
def handle_shell_closed(data):
    token = None
    for t, info in connected_appliances.items():
        if info['sid'] == request.sid:
            token = t
            break
    
    if token and token in shell_sessions:
        console_sid = shell_sessions[token].get('console_sid')
        if console_sid:
            socketio.emit('shell_closed', {'reason': data.get('reason', 'Shell closed')}, 
                         room=console_sid, namespace='/console')
        del shell_sessions[token]


@socketio.on('connect', namespace='/console')
def console_connect():
    pass

@socketio.on('disconnect', namespace='/console')
def console_disconnect():
    tokens_to_close = []
    for token, session in shell_sessions.items():
        if session.get('console_sid') == request.sid:
            tokens_to_close.append(token)
    
    for token in tokens_to_close:
        if token in connected_appliances:
            appliance_sid = connected_appliances[token]['sid']
            socketio.emit('close_shell', {}, room=appliance_sid, namespace='/appliance')
        del shell_sessions[token]

@socketio.on('start_shell', namespace='/console')
def console_start_shell(data):
    appliance_id = data.get('appliance_id')
    
    with app.app_context():
        appliance = Appliance.query.get(appliance_id)
        if not appliance:
            emit('shell_error', {'error': 'Appliance not found'})
            return
        
        token = appliance.token
        if token not in connected_appliances:
            emit('shell_error', {'error': 'Appliance not connected'})
            return
        
        shell_sessions[token] = {
            'console_sid': request.sid,
            'started_at': datetime.utcnow()
        }
        
        appliance_sid = connected_appliances[token]['sid']
        socketio.emit('start_shell', {'cols': data.get('cols', 80), 'rows': data.get('rows', 24)}, 
                     room=appliance_sid, namespace='/appliance')
        
        emit('shell_started', {'appliance_name': appliance.name})
        print(f"[TUNNEL] Shell session started for {appliance.name}")

@socketio.on('shell_input', namespace='/console')
def console_shell_input(data):
    appliance_id = data.get('appliance_id')
    
    with app.app_context():
        appliance = Appliance.query.get(appliance_id)
        if not appliance:
            return
        
        token = appliance.token
        if token not in connected_appliances:
            emit('shell_error', {'error': 'Appliance disconnected'})
            return
        
        appliance_sid = connected_appliances[token]['sid']
        socketio.emit('shell_input', {'input': data.get('input', '')}, 
                     room=appliance_sid, namespace='/appliance')

@socketio.on('resize_shell', namespace='/console')
def console_resize_shell(data):
    appliance_id = data.get('appliance_id')
    
    with app.app_context():
        appliance = Appliance.query.get(appliance_id)
        if not appliance:
            return
        
        token = appliance.token
        if token in connected_appliances:
            appliance_sid = connected_appliances[token]['sid']
            socketio.emit('resize_shell', {'cols': data.get('cols'), 'rows': data.get('rows')}, 
                         room=appliance_sid, namespace='/appliance')

@socketio.on('close_shell', namespace='/console')
def console_close_shell(data):
    appliance_id = data.get('appliance_id')
    
    with app.app_context():
        appliance = Appliance.query.get(appliance_id)
        if not appliance:
            return
        
        token = appliance.token
        if token in connected_appliances:
            appliance_sid = connected_appliances[token]['sid']
            socketio.emit('close_shell', {}, room=appliance_sid, namespace='/appliance')
        
        if token in shell_sessions:
            del shell_sessions[token]


def cleanup_old_data():
    with app.app_context():
        cutoff_date = datetime.utcnow() - timedelta(days=DATA_RETENTION_DAYS)
        
        old_metrics = Metric.query.filter(Metric.timestamp < cutoff_date).delete()
        old_logs = LoginLog.query.filter(LoginLog.timestamp < cutoff_date).delete()
        old_threats = ThreatMetadata.query.filter(ThreatMetadata.timestamp < cutoff_date).delete()
        
        db.session.commit()
        
        if old_metrics or old_logs or old_threats:
            print(f"[CLEANUP] Removed old data: {old_metrics} metrics, {old_logs} login logs, {old_threats} threats")

@app.route('/api/v1/cleanup', methods=['POST'])
@login_required
def run_cleanup():
    cleanup_old_data()
    return jsonify({'status': 'ok', 'message': f'Dados com mais de {DATA_RETENTION_DAYS} dias removidos'})

if __name__ == '__main__':
    init_db()
    cleanup_old_data()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
