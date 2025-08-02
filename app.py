from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
import os
import logging
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

# Configurar logging
logging.basicConfig(level=logging.DEBUG)

# Configurar JWT
app.config['JWT_SECRET_KEY'] = 'tu-clave-secreta-muy-segura-cambia-en-produccion'
app.config['JWT_IDENTITY_CLAIM'] = 'sub'
jwt = JWTManager(app)

# Configurar la base de datos
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "sdgdrdc.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Hacer que la función date esté disponible en los templates de Jinja2
@app.context_processor
def inject_date():
    return {'date': date, 'datetime': datetime}

# Manejadores de errores
@app.errorhandler(422)
def handle_unprocessable_entity(e):
    app.logger.error(f"Error 422: {e}")
    return jsonify({"error": "Entidad No Procesable", "detalles": str(e), "mensaje": "Revisa los datos enviados"}), 422

@app.errorhandler(401)
def handle_unauthorized(e):
    app.logger.error(f"Error 401: {e}")
    return jsonify({"error": "No autorizado", "mensaje": "Token JWT requerido o inválido"}), 401

# Modelos
class Usuario(db.Model):
    __tablename__ = 'Usuario'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False, unique=True)
    contraseña = db.Column(db.Text, nullable=False)
    rol = db.Column(db.Text, nullable=False)

class Protocolo(db.Model):
    __tablename__ = 'Protocolo'
    id_protocolo = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.Text, nullable=False, unique=True)
    descripcion = db.Column(db.Text)

class Criticidad(db.Model):
    __tablename__ = 'Criticidad'
    id_criticidad = db.Column(db.Integer, primary_key=True)
    nivel = db.Column(db.Text, nullable=False, unique=True)
    descripcion = db.Column(db.Text)

class Estado(db.Model):
    __tablename__ = 'Estado'
    id_estado = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.Text, nullable=False, unique=True)
    descripcion = db.Column(db.Text)

class Vulnerabilidad(db.Model):
    __tablename__ = 'Vulnerabilidad'
    id_vulnerabilidad = db.Column(db.Integer, primary_key=True)
    id_protocolo = db.Column(db.Integer, db.ForeignKey('Protocolo.id_protocolo'), nullable=False)
    id_criticidad = db.Column(db.Integer, db.ForeignKey('Criticidad.id_criticidad'), nullable=False)
    id_estado = db.Column(db.Integer, db.ForeignKey('Estado.id_estado'), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    fecha_identificacion = db.Column(db.Date, nullable=False)
    responsable = db.Column(db.Text)
    id_usuario_asignado = db.Column(db.Integer, db.ForeignKey('Usuario.id_usuario'))

def validate_vulnerabilidad_data(data):
    errors = []
    required_fields = ['id_protocolo', 'id_criticidad', 'id_estado', 'descripcion', 'fecha_identificacion']
    
    for field in required_fields:
        if not data.get(field):
            errors.append(f"{field} es requerido")
    
    if 'fecha_identificacion' in data:
        try:
            fecha = datetime.strptime(data['fecha_identificacion'], '%Y-%m-%d').date()
            if fecha > date.today():
                errors.append("fecha_identificacion no puede ser futura")
        except ValueError:
            errors.append("fecha_identificacion debe tener formato YYYY-MM-DD")
    
    with app.app_context():
        for field, model in [('id_protocolo', Protocolo), ('id_criticidad', Criticidad), ('id_estado', Estado)]:
            if data.get(field) and not db.session.get(model, int(data[field])):
                errors.append(f"{field} no existe o es inválido")
        
        if 'id_usuario_asignado' in data and data['id_usuario_asignado'] and not db.session.get(Usuario, int(data['id_usuario_asignado'])):
            errors.append("id_usuario_asignado no existe o es inválido")
    
    return errors

# Rutas
@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        app.logger.error(f"Error al cargar el template: {str(e)}")
        return f'''
        <h1>Error al cargar el template</h1>
        <p>Error: {str(e)}</p>
        <p>Verifica que el archivo 'index.html' esté en la carpeta 'templates'</p>
        '''

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/vulnerabilities')
def vulnerabilities_page():
    return render_template('vulnerabilities.html')

@app.route('/debug')
def debug():
    template_folder = app.template_folder
    static_folder = app.static_folder
    root_path = app.root_path
    
    templates_path = os.path.join(root_path, 'templates')
    static_path = os.path.join(root_path, 'static')
    
    templates_exist = os.path.exists(templates_path)
    static_exist = os.path.exists(static_path)
    
    template_files = os.listdir(templates_path) if templates_exist else []
    static_files = []
    if static_exist:
        for root, dirs, files in os.walk(static_path):
            level = root.replace(static_path, '').count(os.sep)
            indent = ' ' * 2 * level
            static_files.append(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 2 * (level + 1)
            for file in files:
                static_files.append(f"{subindent}{file}")
    
    return f'''
    <h1>Información de Debug - Sistema SDGDRDC</h1>
    <p><strong>Root Path:</strong> {root_path}</p>
    <p><strong>Template Folder:</strong> {template_folder}</p>
    <p><strong>Static Folder:</strong> {static_folder}</p>
    <hr>
    <h2>Estructura del Proyecto:</h2>
    <p><strong>Templates Path:</strong> {templates_path}</p>
    <p><strong>Templates Folder Exists:</strong> {templates_exist}</p>
    <p><strong>Template Files:</strong> {template_files}</p>
    <br>
    <p><strong>Static Path:</strong> {static_path}</p>
    <p><strong>Static Folder Exists:</strong> {static_exist}</p>
    <p><strong>Static Files:</strong></p>
    <pre>{"<br>".join(static_files) if static_files else "No files found"}</pre>
    <hr>
    <h2>Rutas Disponibles:</h2>
    <ul>
        <li><a href="/">/ - Página principal</a></li>
        <li><a href="/dashboard">/dashboard - Dashboard</a></li>
        <li><a href="/reports">/reports - Reportes</a></li>
        <li><a href="/vulnerabilities">/vulnerabilities - Vulnerabilidades</a></li>
        <li>/login - Login (POST)</li>
        <li>/api/vulnerabilidades - API Vulnerabilidades (requiere JWT)</li>
        <li>/api/protocolos - API Protocolos</li>
        <li>/api/criticidades - API Criticidades</li>
        <li>/api/estados - API Estados</li>
        <li>/api/usuarios - API Usuarios</li>
    </ul>
    '''

@app.route('/login', methods=['POST'])
def login():
    app.logger.info("Solicitud de login recibida")
    
    try:
        data = request.get_json()
        if not data:
            app.logger.error("No se recibieron datos JSON")
            return jsonify({'error': 'Faltan credenciales'}), 400
        
        email = data.get('email')
        password = data.get('password') or data.get('contraseña')
        
        if not email or not password:
            app.logger.error("Email o contraseña faltantes")
            return jsonify({'error': 'Faltan credenciales'}), 400
        
        app.logger.debug(f"Intentando login para email: {email}")
        
        user = Usuario.query.filter_by(email=email).first()
        if user and check_password_hash(user.contraseña, password):
            identity = str(user.id_usuario)
            access_token = create_access_token(identity=identity)
            
            app.logger.info(f"Login exitoso para usuario: {user.email}")
            return jsonify({
                'token': access_token,
                'usuario': user.nombre,
                'rol': user.rol,
                'message': 'Login exitoso'
            }), 200
        
        app.logger.error(f"Login fallido para email: {email}")
        return jsonify({'error': 'Credenciales inválidas'}), 401
        
    except Exception as e:
        app.logger.error(f"Error en login: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/api/vulnerabilidades', methods=['GET', 'POST'])
@jwt_required()
def vulnerabilidades():
    current_user_id = get_jwt_identity()
    app.logger.info(f"Usuario autenticado: {current_user_id}")
    app.logger.info(f"Solicitud a /api/vulnerabilidades - Método: {request.method}")
    
    if request.method == 'POST':
        app.logger.info("Procesando POST para crear vulnerabilidad")
        try:
            data = request.get_json() or request.form.to_dict()
            app.logger.debug(f"Datos recibidos: {data}")
            
            errors = validate_vulnerabilidad_data(data)
            if errors:
                app.logger.error(f"Errores de validación: {errors}")
                return jsonify({'error': 'Validación fallida', 'details': errors}), 422
            
            nueva_vulnerabilidad = Vulnerabilidad(
                id_protocolo=int(data['id_protocolo']),
                id_criticidad=int(data['id_criticidad']),
                id_estado=int(data['id_estado']),
                descripcion=data['descripcion'],
                fecha_identificacion=datetime.strptime(data['fecha_identificacion'], '%Y-%m-%d').date(),
                responsable=data.get('responsable'),
                id_usuario_asignado=int(data['id_usuario_asignado']) if data.get('id_usuario_asignado') else None
            )
            db.session.add(nueva_vulnerabilidad)
            db.session.flush()  # Verificar asignación de ID
            app.logger.info(f"Vulnerabilidad creada temporalmente con ID: {nueva_vulnerabilidad.id_vulnerabilidad}")
            db.session.commit()  # Asegurar persistencia
            app.logger.info(f"Vulnerabilidad persistida con ID: {nueva_vulnerabilidad.id_vulnerabilidad}")
            return jsonify({'message': 'Vulnerabilidad creada', 'id': nueva_vulnerabilidad.id_vulnerabilidad}), 201
        except ValueError as ve:
            app.logger.error(f"Error de valor: {str(ve)}", exc_info=True)
            db.session.rollback()
            return jsonify({'error': 'Datos inválidos: asegúrese de enviar valores numéricos correctos', 'details': str(ve)}), 422
        except IntegrityError as ie:
            app.logger.error(f"Error de integridad: {str(ie)}", exc_info=True)
            db.session.rollback()
            return jsonify({'error': 'Error de integridad en la base de datos', 'details': str(ie)}), 400
        except Exception as e:
            app.logger.error(f"Error interno: {str(e)}", exc_info=True)
            db.session.rollback()
            return jsonify({'error': f'Error interno: {str(e)}', 'details': 'Revise los logs del servidor'}), 500
    
    elif request.method == 'GET':
        app.logger.info("Procesando GET para obtener vulnerabilidades")
        try:
            vulnerabilidades = db.session.query(
                Vulnerabilidad,
                Usuario.nombre.label('usuario_nombre'),
                Protocolo.nombre.label('protocolo_nombre'),
                Criticidad.nivel.label('criticidad_nombre'),
                Estado.nombre.label('estado_nombre')
            ).outerjoin(Usuario, Vulnerabilidad.id_usuario_asignado == Usuario.id_usuario)\
             .join(Protocolo, Vulnerabilidad.id_protocolo == Protocolo.id_protocolo)\
             .join(Criticidad, Vulnerabilidad.id_criticidad == Criticidad.id_criticidad)\
             .join(Estado, Vulnerabilidad.id_estado == Estado.id_estado).all()
            
            resultado = [{
                'id_vulnerabilidad': v.Vulnerabilidad.id_vulnerabilidad,
                'protocolo_nombre': v.protocolo_nombre,
                'criticidad_nombre': v.criticidad_nombre,
                'estado_nombre': v.estado_nombre,
                'descripcion': v.Vulnerabilidad.descripcion,
                'fecha_identificacion': v.Vulnerabilidad.fecha_identificacion.strftime('%Y-%m-%d'),
                'responsable': v.Vulnerabilidad.responsable,
                'usuario_nombre': v.usuario_nombre or 'Sin asignar'
            } for v in vulnerabilidades]
            
            app.logger.info(f"Devolviendo {len(resultado)} vulnerabilidades")
            return jsonify(resultado), 200
        except Exception as e:
            app.logger.error(f"Error obteniendo vulnerabilidades: {str(e)}", exc_info=True)
            return jsonify({'error': f'Error interno: {str(e)}'}), 500
    
    return jsonify({'error': 'Método no permitido'}), 405

@app.route('/api/vulnerabilidades/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def vulnerabilidad_id(id):
    current_user_id = get_jwt_identity()
    app.logger.info(f"Usuario autenticado: {current_user_id}")
    app.logger.info(f"Solicitud a /api/vulnerabilidades/{id} - Método: {request.method}")
    
    vulnerabilidad = Vulnerabilidad.query.get_or_404(id)
    
    if request.method == 'GET':
        try:
            v = db.session.query(
                Vulnerabilidad,
                Usuario.nombre.label('usuario_nombre'),
                Protocolo.nombre.label('protocolo_nombre'),
                Criticidad.nivel.label('criticidad_nombre'),
                Estado.nombre.label('estado_nombre')
            ).outerjoin(Usuario, Vulnerabilidad.id_usuario_asignado == Usuario.id_usuario)\
             .join(Protocolo, Vulnerabilidad.id_protocolo == Protocolo.id_protocolo)\
             .join(Criticidad, Vulnerabilidad.id_criticidad == Criticidad.id_criticidad)\
             .join(Estado, Vulnerabilidad.id_estado == Estado.id_estado)\
             .filter(Vulnerabilidad.id_vulnerabilidad == id).first()
            
            return jsonify({
                'id_vulnerabilidad': v.Vulnerabilidad.id_vulnerabilidad,
                'protocolo_nombre': v.protocolo_nombre,
                'criticidad_nombre': v.criticidad_nombre,
                'estado_nombre': v.estado_nombre,
                'descripcion': v.Vulnerabilidad.descripcion,
                'fecha_identificacion': v.Vulnerabilidad.fecha_identificacion.strftime('%Y-%m-%d'),
                'responsable': v.Vulnerabilidad.responsable,
                'usuario_nombre': v.usuario_nombre or 'Sin asignar'
            }), 200
        except Exception as e:
            app.logger.error(f"Error obteniendo vulnerabilidad {id}: {str(e)}", exc_info=True)
            return jsonify({'error': f'Error interno: {str(e)}'}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.get_json() or request.form.to_dict()
            app.logger.debug(f"Datos para actualizar: {data}")
            
            errors = validate_vulnerabilidad_data(data)
            if errors:
                app.logger.error(f"Errores de validación: {errors}")
                return jsonify({'error': 'Validación fallida', 'details': errors}), 422
            
            vulnerabilidad.id_protocolo = int(data.get('id_protocolo', vulnerabilidad.id_protocolo))
            vulnerabilidad.id_criticidad = int(data.get('id_criticidad', vulnerabilidad.id_criticidad))
            vulnerabilidad.id_estado = int(data.get('id_estado', vulnerabilidad.id_estado))
            vulnerabilidad.descripcion = data.get('descripcion', vulnerabilidad.descripcion)
            if 'fecha_identificacion' in data:
                vulnerabilidad.fecha_identificacion = datetime.strptime(data['fecha_identificacion'], '%Y-%m-%d').date()
            vulnerabilidad.responsable = data.get('responsable', vulnerabilidad.responsable)
            if 'id_usuario_asignado' in data and data['id_usuario_asignado']:
                vulnerabilidad.id_usuario_asignado = int(data['id_usuario_asignado'])
            elif 'id_usuario_asignado' in data and not data['id_usuario_asignado']:
                vulnerabilidad.id_usuario_asignado = None
            
            db.session.commit()  # Asegurar persistencia
            app.logger.info(f"Vulnerabilidad {id} actualizada")
            return jsonify({'message': 'Vulnerabilidad actualizada', 'id': vulnerabilidad.id_vulnerabilidad}), 200
        except ValueError as ve:
            app.logger.error(f"Error de valor: {str(ve)}", exc_info=True)
            db.session.rollback()
            return jsonify({'error': 'Datos inválidos: asegúrese de enviar valores numéricos correctos', 'details': str(ve)}), 422
        except IntegrityError as ie:
            app.logger.error(f"Error de integridad: {str(ie)}", exc_info=True)
            db.session.rollback()
            return jsonify({'error': 'Error de integridad en la base de datos', 'details': str(ie)}), 400
        except Exception as e:
            app.logger.error(f"Error actualizando vulnerabilidad {id}: {str(e)}", exc_info=True)
            db.session.rollback()
            return jsonify({'error': f'Error interno: {str(e)}', 'details': 'Revise los logs del servidor'}), 500
    
    elif request.method == 'DELETE':
        try:
            db.session.delete(vulnerabilidad)
            db.session.commit()  # Asegurar persistencia
            app.logger.info(f"Vulnerabilidad {id} eliminada")
            return jsonify({'message': 'Vulnerabilidad eliminada'}), 200
        except Exception as e:
            app.logger.error(f"Error eliminando vulnerabilidad {id}: {str(e)}", exc_info=True)
            db.session.rollback()
            return jsonify({'error': f'Error interno: {str(e)}', 'details': 'Revise los logs del servidor'}), 500
    
    return jsonify({'error': 'Método no permitido'}), 405

@app.route('/api/protocolos', methods=['GET'])
def get_protocolos():
    protocolos = Protocolo.query.all()
    return jsonify([{
        'id_protocolo': p.id_protocolo,
        'nombre': p.nombre,
        'descripcion': p.descripcion
    } for p in protocolos])

@app.route('/api/criticidades', methods=['GET'])
def get_criticidades():
    criticidades = Criticidad.query.all()
    return jsonify([{
        'id_criticidad': c.id_criticidad,
        'nivel': c.nivel,
        'descripcion': c.descripcion
    } for c in criticidades])

@app.route('/api/estados', methods=['GET'])
def get_estados():
    estados = Estado.query.all()
    return jsonify([{
        'id_estado': e.id_estado,
        'nombre': e.nombre,
        'descripcion': e.descripcion
    } for e in estados])

@app.route('/api/usuarios', methods=['GET'])
@jwt_required()
def get_usuarios():
    current_user_id = get_jwt_identity()
    app.logger.info(f"Usuario autenticado consultando usuarios: {current_user_id}")
    
    usuarios = Usuario.query.all()
    return jsonify([{
        'id_usuario': u.id_usuario,
        'nombre': u.nombre,
        'email': u.email,
        'rol': u.rol
    } for u in usuarios])

@app.route('/api/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    current_user_id = get_jwt_identity()
    user = Usuario.query.get(int(current_user_id))
    
    if user:
        return jsonify({
            'valid': True,
            'user_id': current_user_id,
            'nombre': user.nombre,
            'email': user.email,
            'rol': user.rol,
            'message': 'Token válido'
        }), 200
    else:
        return jsonify({'valid': False, 'message': 'Usuario no encontrado'}), 404

if __name__ == '__main__':
    with app.app_context():
        inspector = inspect(db.engine)
        
        # Verificar si la base de datos existe y tiene la tabla Vulnerabilidad
        if not os.path.exists(os.path.join(basedir, 'sdgdrdc.db')) or not inspector.has_table('Vulnerabilidad'):
            db.create_all()
            app.logger.info("Base de datos creada o reiniciada")
            if not Usuario.query.first():
                app.logger.info("Inicializando datos por defecto")
                db.session.add(Usuario(nombre='Admin', email='admin@uniminuto.edu', contraseña=generate_password_hash('admin123'), rol='admin'))
                db.session.add(Protocolo(nombre='SMB', descripcion='Server Message Block'))
                db.session.add(Protocolo(nombre='TLS', descripcion='Transport Layer Security'))
                db.session.add(Protocolo(nombre='SSL', descripcion='Secure Sockets Layer'))
                db.session.add(Criticidad(nivel='Baja', descripcion='Impacto mínimo'))
                db.session.add(Criticidad(nivel='Media', descripcion='Impacto moderado'))
                db.session.add(Criticidad(nivel='Alta', descripcion='Impacto significativo'))
                db.session.add(Criticidad(nivel='Crítica', descripcion='Impacto crítico'))
                db.session.add(Estado(nombre='Identificada', descripcion='Recién detectada'))
                db.session.add(Estado(nombre='En análisis', descripcion='En evaluación'))
                db.session.add(Estado(nombre='En remediación', descripcion='En corrección'))
                db.session.add(Estado(nombre='Resuelta', descripcion='Solucionada'))
                db.session.add(Estado(nombre='Cerrada', descripcion='Finalizada'))
                db.session.commit()
                app.logger.info("Datos por defecto inicializados")
        else:
            app.logger.info("Base de datos existente detectada, no se reiniciarán los datos")

    print("=" * 60)
    print("🚀 SISTEMA DE GESTIÓN DE RIESGOS - SDGDRDC")
    print("=" * 60)
    print("✅ CORRECCIONES APLICADAS:")
    print("   • Login acepta 'password' y 'contraseña'")
    print("   • JWT identity como string simple")
    print("   • Manejo de errores mejorado con excepciones específicas")
    print("   • Clave JWT fija para desarrollo")
    print("   • Persistencia en base de datos asegurada con commit/rollback y flush")
    print("   • Corrección de has_table con inspect()")
    print("=" * 60)
    print("🌐 URLs disponibles:")
    print("   http://127.0.0.1:5000/               → Página principal")
    print("   http://127.0.0.1:5000/dashboard      → Dashboard")
    print("   http://127.0.0.1:5000/reports        → Reportes")
    print("   http://127.0.0.1:5000/vulnerabilities → Vulnerabilidades")
    print("   http://127.0.0.1:5000/debug          → Información de debug")
    print("=" * 60)
    print("📊 Credenciales por defecto:")
    print("   Email: admin@uniminuto.edu")
    print("   Contraseña: admin123")
    print("=" * 60)
    print("🔧 PARA USAR LA API:")
    print("   1. POST /login con: {\"email\": \"admin@uniminuto.edu\", \"password\": \"admin123\"}")
    print("   2. Usar token en header: Authorization: Bearer TOKEN")
    print("   3. Verifique los logs si hay errores de validación o persistencia")
    print("=" * 60)
    
    app.run(debug=True)