from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
import logging
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from apscheduler.schedulers.background import BackgroundScheduler
import shutil

# Configurar logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')

# Configurar JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.urandom(32).hex())  # Clave segura por defecto
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_IDENTITY_CLAIM'] = 'sub'
jwt = JWTManager(app)

# Configurar la base de datos
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "sdgdrdc.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Hacer que la función date esté disponible en los templates
@app.context_processor
def inject_date():
    return {'date': date, 'datetime': datetime}

# Manejadores de errores
@app.errorhandler(422)
def handle_unprocessable_entity(e):
    logger.error(f"Error 422: {str(e)}", exc_info=True)
    return jsonify({"error": "Entidad No Procesable", "mensaje": "Revisa los datos enviados o el token"}), 422

@app.errorhandler(401)
def handle_unauthorized(e):
    logger.error(f"Error 401: {str(e)}", exc_info=True)
    return jsonify({"error": "No autorizado", "mensaje": "Token JWT requerido o inválido, inicia sesión"}), 401

@app.errorhandler(404)
def handle_not_found(e):
    logger.error(f"Error 404: {str(e)}", exc_info=True)
    return jsonify({"error": "Recurso no encontrado", "mensaje": "La ruta solicitada no existe"}), 404

@app.errorhandler(500)
def handle_internal_server_error(e):
    logger.error(f"Error 500: {str(e)}", exc_info=True)
    return jsonify({"error": "Error interno del servidor", "mensaje": "Contacte al administrador, revisa los logs"}), 500

# Modelos
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    contraseña = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(50), nullable=False)

class Protocolo(db.Model):
    __tablename__ = 'protocolos'
    id_protocolo = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False, unique=True)
    descripcion = db.Column(db.Text)

class Criticidad(db.Model):
    __tablename__ = 'criticidades'
    id_criticidad = db.Column(db.Integer, primary_key=True)
    nivel = db.Column(db.String(50), nullable=False, unique=True)
    descripcion = db.Column(db.Text)

class Estado(db.Model):
    __tablename__ = 'estados'
    id_estado = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False, unique=True)
    descripcion = db.Column(db.Text)

class Vulnerabilidad(db.Model):
    __tablename__ = 'vulnerabilidades'
    id_vulnerabilidad = db.Column(db.Integer, primary_key=True)
    id_protocolo = db.Column(db.Integer, db.ForeignKey('protocolos.id_protocolo'), nullable=False)
    id_criticidad = db.Column(db.Integer, db.ForeignKey('criticidades.id_criticidad'), nullable=False)
    id_estado = db.Column(db.Integer, db.ForeignKey('estados.id_estado'), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    fecha_identificacion = db.Column(db.Date, nullable=False)
    responsable = db.Column(db.String(100))
    id_usuario_asignado = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'))

class Seguimiento(db.Model):
    __tablename__ = 'seguimientos'
    id_seguimiento = db.Column(db.Integer, primary_key=True)
    id_vulnerabilidad = db.Column(db.Integer, db.ForeignKey('vulnerabilidades.id_vulnerabilidad'), nullable=False)
    accion = db.Column(db.String(100), nullable=False)
    fecha_accion = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False)
    comentarios = db.Column(db.Text)

def validate_vulnerabilidad_data(data):
    errors = []
    required_fields = ['id_protocolo', 'id_criticidad', 'id_estado', 'descripcion', 'fecha_identificacion']
    
    for field in required_fields:
        value = data.get(field)
        if not value or str(value).strip() in ('', 'null', 'undefined'):
            errors.append(f"{field} es requerido")
        elif field in ['id_protocolo', 'id_criticidad', 'id_estado']:
            try:
                int_value = int(str(value).strip())
                if int_value <= 0:
                    errors.append(f"{field} debe ser un número positivo")
            except (ValueError, TypeError):
                errors.append(f"{field} debe ser un número válido")

    if 'fecha_identificacion' in data:
        value = data.get('fecha_identificacion')
        if not value or str(value).strip() in ('', 'null', 'undefined'):
            errors.append("fecha_identificacion es requerido")
        else:
            try:
                fecha = datetime.strptime(str(value).strip(), '%Y-%m-%d').date()
                if fecha > date.today():
                    errors.append("fecha_identificacion no puede ser futura")
            except (ValueError, TypeError):
                errors.append("fecha_identificacion debe ser YYYY-MM-DD")

    with app.app_context():
        for field, model in [('id_protocolo', Protocolo), ('id_criticidad', Criticidad), ('id_estado', Estado)]:
            value = data.get(field)
            if value and str(value).strip() not in ('', 'null', 'undefined'):
                try:
                    int_value = int(str(value).strip())
                    if not db.session.get(model, int_value):
                        errors.append(f"{field} no existe o es inválido")
                except (ValueError, TypeError):
                    errors.append(f"{field} debe ser un número válido")

        if 'id_usuario_asignado' in data and data['id_usuario_asignado']:
            value = data.get('id_usuario_asignado')
            if str(value).strip() not in ('', 'null', 'undefined'):
                try:
                    int_value = int(str(value).strip())
                    if int_value and not db.session.get(Usuario, int_value):
                        errors.append("id_usuario_asignado no existe o es inválido")
                except (ValueError, TypeError):
                    errors.append("id_usuario_asignado debe ser un número válido")

    return errors

# Rutas
@app.route('/')
def index():
    try:
        logger.info("Accediendo a la página principal")
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error al cargar index.html: {str(e)}", exc_info=True)
        return f"Error al cargar el template: {str(e)}", 500

@app.route('/welcome', methods=['GET'])
def welcome():
    logger.info("Accediendo a la página de bienvenida")
    return jsonify({
        "message": "Bienvenido al Sistema SDGDRDC. Por favor, inicia sesión en /login con tus credenciales.",
        "login_url": "/login"
    }), 200

@app.route('/dashboard')
@jwt_required()
def dashboard():
    logger.info("Accediendo a la página de dashboard")
    try:
        return render_template('dashboard.html')
    except Exception as e:
        logger.error(f"Error al cargar dashboard.html: {str(e)}", exc_info=True)
        return jsonify({"error": "Error al cargar la página", "mensaje": str(e)}), 500

@app.route('/reports')
@jwt_required()
def reports():
    logger.info("Accediendo a la página de reportes")
    try:
        return render_template('reports.html')
    except Exception as e:
        logger.error(f"Error al cargar reports.html: {str(e)}", exc_info=True)
        return jsonify({"error": "Error al cargar la página", "mensaje": str(e)}), 500

@app.route('/vulnerabilities')
@jwt_required()
def vulnerabilities_page():
    logger.info("Accediendo a la página de vulnerabilidades")
    try:
        return render_template('vulnerabilities.html')
    except Exception as e:
        logger.error(f"Error al cargar vulnerabilities.html: {str(e)}", exc_info=True)
        return jsonify({"error": "Error al cargar la página", "mensaje": str(e)}), 500

@app.route('/debug')
def debug():
    logger.info("Accediendo a la página de debug")
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
            indent = ' ' * 4 * level
            static_files.append(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 4 * (level + 1)
            for file in files:
                static_files.append(f"{subindent}{file}")
    
    return render_template('debug.html', 
                          root_path=root_path, 
                          template_folder=template_folder, 
                          static_folder=static_folder,
                          templates_path=templates_path,
                          templates_exist=templates_exist,
                          template_files=template_files,
                          static_path=static_path,
                          static_exist=static_exist,
                          static_files=static_files)

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/login', methods=['POST'])
def login():
    logger.info("Solicitud de login recibida")
    try:
        data = request.get_json()
        if not data:
            logger.error("No se recibieron datos JSON")
            return jsonify({'error': 'Faltan credenciales'}), 400
        
        email = data.get('email')
        password = data.get('password') or data.get('contraseña')
        
        if not email or not password:
            logger.error("Email o contraseña faltantes")
            return jsonify({'error': 'Faltan credenciales'}), 400
        
        logger.debug(f"Intentando login para email: {email}")
        
        user = db.session.execute(db.select(Usuario).filter_by(email=email)).scalar_one_or_none()
        if not user:
            logger.error(f"Usuario no encontrado para email: {email}")
            return jsonify({'error': 'Credenciales inválidas'}), 401
        
        if check_password_hash(user.contraseña, password):
            identity = str(user.id_usuario)
            access_token = create_access_token(identity=identity)
            logger.info(f"Login exitoso para usuario: {user.email}")
            return jsonify({
                'token': access_token,
                'usuario': user.nombre,
                'rol': user.rol,
                'message': 'Login exitoso'
            }), 200
        
        logger.error(f"Contraseña incorrecta para email: {email}")
        return jsonify({'error': 'Credenciales inválidas'}), 401
        
    except Exception as e:
        logger.error(f"Error en login: {str(e)} - Detalles: {repr(e)}", exc_info=True)
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/api/vulnerabilidades', methods=['GET', 'POST'])
@jwt_required()
def vulnerabilidades():
    current_user_id = get_jwt_identity()
    logger.info(f"Solicitud a /api/vulnerabilidades - Método: {request.method} - Usuario: {current_user_id}")

    if request.method == 'POST':
        logger.info(f"Procesando POST para usuario: {current_user_id} - Datos recibidos: {request.get_json() or request.form.to_dict()}")
        try:
            data = request.get_json() or request.form.to_dict()
            errors = validate_vulnerabilidad_data(data)
            if errors:
                logger.error(f"Validación fallida: {errors}")
                return jsonify({'error': 'Validación fallida', 'details': errors}), 422

            nueva_vulnerabilidad = Vulnerabilidad(
                id_protocolo=int(data['id_protocolo']),
                id_criticidad=int(data['id_criticidad']),
                id_estado=int(data['id_estado']),
                descripcion=data['descripcion'],
                fecha_identificacion=datetime.strptime(data['fecha_identificacion'], '%Y-%m-%d').date(),
                responsable=data.get('responsable'),
                id_usuario_asignado=current_user_id if not data.get('id_usuario_asignado') else int(data.get('id_usuario_asignado'))
            )
            db.session.add(nueva_vulnerabilidad)
            db.session.flush()
            logger.info(f"Vulnerabilidad creada temporalmente con ID: {nueva_vulnerabilidad.id_vulnerabilidad}")
            db.session.commit()
            logger.info(f"Vulnerabilidad persistida con ID: {nueva_vulnerabilidad.id_vulnerabilidad}")
            return jsonify({'message': 'Vulnerabilidad creada', 'id': nueva_vulnerabilidad.id_vulnerabilidad}), 201
        except (ValueError, TypeError) as e:
            db.session.rollback()
            logger.error(f"Error de valor: {str(e)}", exc_info=True)
            return jsonify({'error': 'Datos inválidos', 'details': str(e)}), 422
        except IntegrityError as e:
            db.session.rollback()
            logger.error(f"Error de integridad: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error de integridad', 'details': str(e)}), 400
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error interno: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error interno', 'details': str(e)}), 500

    elif request.method == 'GET':
        logger.info(f"Procesando GET para usuario: {current_user_id}")
        try:
            vulnerabilidades = db.session.execute(
                db.select(Vulnerabilidad, Usuario.nombre.label('usuario_nombre'), Protocolo.nombre.label('protocolo_nombre'),
                         Criticidad.nivel.label('criticidad_nombre'), Estado.nombre.label('estado_nombre'))
                .outerjoin(Usuario, Vulnerabilidad.id_usuario_asignado == Usuario.id_usuario)
                .join(Protocolo)
                .join(Criticidad)
                .join(Estado)
            ).all()
            resultado = [{
                'id_vulnerabilidad': v[0].id_vulnerabilidad,
                'protocolo_nombre': v[2],
                'criticidad_nombre': v[3],
                'estado_nombre': v[4],
                'descripcion': v[0].descripcion,
                'fecha_identificacion': v[0].fecha_identificacion.strftime('%Y-%m-%d'),
                'responsable': v[0].responsable,
                'usuario_nombre': v[1] or 'Sin asignar'
            } for v in vulnerabilidades]
            logger.info(f"Devolviendo {len(resultado)} vulnerabilidades")
            return jsonify(resultado), 200
        except Exception as e:
            logger.error(f"Error obteniendo vulnerabilidades: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error interno', 'details': str(e)}), 500

@app.route('/api/vulnerabilidades/<int:id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def vulnerabilidad_id(id):
    current_user_id = get_jwt_identity()
    logger.info(f"Solicitud a /api/vulnerabilidades/{id} - Método: {request.method} - Usuario: {current_user_id}")

    vulnerabilidad = db.session.get(Vulnerabilidad, id)
    if not vulnerabilidad:
        return jsonify({'error': 'Recurso no encontrado'}), 404

    if vulnerabilidad.id_usuario_asignado != current_user_id:
        return jsonify({'error': 'No autorizado'}), 403

    if request.method == 'GET':
        try:
            v = db.session.execute(
                db.select(Vulnerabilidad, Usuario.nombre.label('usuario_nombre'), Protocolo.nombre.label('protocolo_nombre'),
                         Criticidad.nivel.label('criticidad_nombre'), Estado.nombre.label('estado_nombre'))
                .outerjoin(Usuario, Vulnerabilidad.id_usuario_asignado == Usuario.id_usuario)
                .join(Protocolo)
                .join(Criticidad)
                .join(Estado)
                .filter(Vulnerabilidad.id_vulnerabilidad == id)
            ).first()
            if not v:
                return jsonify({'error': 'Recurso no encontrado'}), 404
            return jsonify({
                'id_vulnerabilidad': v[0].id_vulnerabilidad,
                'id_protocolo': v[0].id_protocolo,
                'id_criticidad': v[0].id_criticidad,
                'id_estado': v[0].id_estado,
                'protocolo_nombre': v[2],
                'criticidad_nombre': v[3],
                'estado_nombre': v[4],
                'descripcion': v[0].descripcion,
                'fecha_identificacion': v[0].fecha_identificacion.strftime('%Y-%m-%d'),
                'responsable': v[0].responsable,
                'usuario_nombre': v[1] or 'Sin asignar'
            }), 200
        except Exception as e:
            logger.error(f"Error obteniendo vulnerabilidad {id}: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error interno', 'details': str(e)}), 500

    elif request.method == 'PUT':
        try:
            data = request.get_json() or request.form.to_dict()
            logger.debug(f"Datos recibidos para PUT: {data}")
            errors = validate_vulnerabilidad_data(data)
            if errors:
                logger.error(f"Validación fallida: {errors}")
                return jsonify({'error': 'Validación fallida', 'details': errors}), 422

            nuevo_estado = data.get('id_estado')
            estado_actual = vulnerabilidad.id_estado
            fecha_ident = vulnerabilidad.fecha_identificacion
            criticidad = db.session.get(Criticidad, vulnerabilidad.id_criticidad)

            # Validar transiciones según reglas de negocio
            estado_nombres = {'Identificada': 1, 'En análisis': 2, 'En remediación': 3, 'Resuelta': 4, 'Cerrada': 5}
            estado_actual_nombre = db.session.get(Estado, estado_actual).nombre
            nuevo_estado_nombre = db.session.get(Estado, int(nuevo_estado)).nombre if nuevo_estado else estado_actual_nombre

            if nuevo_estado:
                if nuevo_estado_nombre == 'En análisis' and estado_actual_nombre != 'Identificada':
                    return jsonify({'error': 'Solo se puede pasar de Identificada a En análisis'}), 400
                elif nuevo_estado_nombre == 'En remediación' and estado_actual_nombre != 'En análisis':
                    return jsonify({'error': 'Solo se puede pasar de En análisis a En remediación'}), 400
                elif nuevo_estado_nombre == 'En remediación' and criticidad.nivel not in ['Media', 'Alta', 'Crítica']:
                    return jsonify({'error': 'La criticidad debe ser Media o superior para En remediación'}), 400
                elif nuevo_estado_nombre == 'Resuelta' and estado_actual_nombre != 'En remediación':
                    return jsonify({'error': 'Solo se puede pasar de En remediación a Resuelta'}), 400
                elif nuevo_estado_nombre == 'Resuelta' and (date.today() - fecha_ident).days < 30:
                    return jsonify({'error': 'Deben pasar al menos 30 días desde la identificación para marcar como Resuelta'}), 400
                elif nuevo_estado_nombre == 'Cerrada' and estado_actual_nombre != 'Resuelta':
                    return jsonify({'error': 'Solo se puede pasar de Resuelta a Cerrada'}), 400
                elif nuevo_estado_nombre == 'Cerrada':
                    ultimo_seguimiento = db.session.query(Seguimiento).filter_by(id_vulnerabilidad=id).order_by(Seguimiento.fecha_accion.desc()).first()
                    if ultimo_seguimiento and (datetime.utcnow() - ultimo_seguimiento.fecha_accion).days < 7:
                        return jsonify({'error': 'Deben pasar 7 días sin cambios para cerrar'}), 400

            vulnerabilidad.id_protocolo = int(data.get('id_protocolo', vulnerabilidad.id_protocolo))
            vulnerabilidad.id_criticidad = int(data.get('id_criticidad', vulnerabilidad.id_criticidad))
            vulnerabilidad.id_estado = int(nuevo_estado) if nuevo_estado else vulnerabilidad.id_estado
            vulnerabilidad.descripcion = data.get('descripcion', vulnerabilidad.descripcion)
            if 'fecha_identificacion' in data:
                vulnerabilidad.fecha_identificacion = datetime.strptime(data['fecha_identificacion'], '%Y-%m-%d').date()
            vulnerabilidad.responsable = data.get('responsable', vulnerabilidad.responsable)
            vulnerabilidad.id_usuario_asignado = int(data.get('id_usuario_asignado')) if data.get('id_usuario_asignado') else current_user_id

            if nuevo_estado and int(nuevo_estado) != estado_actual:
                seguimiento = Seguimiento(
                    id_vulnerabilidad=id,
                    accion=f"Cambio a {nuevo_estado_nombre}",
                    id_usuario=current_user_id,
                    comentarios=data.get('comentarios', 'Sin comentarios')
                )
                db.session.add(seguimiento)
            db.session.commit()
            return jsonify({'message': 'Vulnerabilidad actualizada', 'id': vulnerabilidad.id_vulnerabilidad}), 200
        except (ValueError, TypeError) as e:
            db.session.rollback()
            logger.error(f"Error de valor: {str(e)}", exc_info=True)
            return jsonify({'error': 'Datos inválidos', 'details': str(e)}), 422
        except IntegrityError as e:
            db.session.rollback()
            logger.error(f"Error de integridad: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error de integridad', 'details': str(e)}), 400
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error interno: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error interno', 'details': str(e)}), 500

    elif request.method == 'DELETE':
        try:
            db.session.delete(vulnerabilidad)
            db.session.commit()
            return jsonify({'message': 'Vulnerabilidad eliminada'}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error eliminando: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error interno', 'details': str(e)}), 500

@app.route('/api/seguimientos', methods=['GET', 'POST'])
@jwt_required()
def seguimientos():
    current_user_id = get_jwt_identity()
    logger.info(f"Solicitud a /api/seguimientos - Método: {request.method} - Usuario: {current_user_id}")

    if request.method == 'POST':
        logger.info(f"Procesando POST para usuario: {current_user_id} - Datos recibidos: {request.get_json() or request.form.to_dict()}")
        try:
            data = request.get_json() or request.form.to_dict()
            required_fields = ['id_vulnerabilidad', 'accion', 'id_usuario']
            if not all(field in data for field in required_fields):
                return jsonify({'error': 'Faltan campos obligatorios: id_vulnerabilidad, accion, id_usuario'}), 400

            nuevo_seguimiento = Seguimiento(
                id_vulnerabilidad=int(data['id_vulnerabilidad']),
                accion=data['accion'],
                id_usuario=int(data['id_usuario']),
                comentarios=data.get('comentarios', '')
            )
            db.session.add(nuevo_seguimiento)
            db.session.commit()
            logger.info(f"Seguimiento creado con ID: {nuevo_seguimiento.id_seguimiento}")
            return jsonify({'message': 'Seguimiento creado', 'id': nuevo_seguimiento.id_seguimiento}), 201
        except (ValueError, TypeError) as e:
            db.session.rollback()
            logger.error(f"Error de valor: {str(e)}", exc_info=True)
            return jsonify({'error': 'Datos inválidos', 'details': str(e)}), 422
        except IntegrityError as e:
            db.session.rollback()
            logger.error(f"Error de integridad: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error de integridad', 'details': str(e)}), 400
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error interno: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error interno', 'details': str(e)}), 500

    elif request.method == 'GET':
        logger.info(f"Procesando GET para usuario: {current_user_id}")
        try:
            seguimientos = db.session.execute(
                db.select(Seguimiento, Vulnerabilidad.descripcion.label('vulnerabilidad_descripcion'), Usuario.nombre.label('usuario_nombre'))
                .join(Vulnerabilidad)
                .join(Usuario)
            ).all()
            resultado = [{
                'id_seguimiento': s[0].id_seguimiento,
                'id_vulnerabilidad': s[0].id_vulnerabilidad,
                'accion': s[0].accion,
                'fecha_accion': s[0].fecha_accion.strftime('%Y-%m-%d %H:%M:%S'),
                'id_usuario': s[0].id_usuario,
                'comentarios': s[0].comentarios,
                'vulnerabilidad_descripcion': s[1],
                'usuario_nombre': s[2]
            } for s in seguimientos]
            logger.info(f"Devolviendo {len(resultado)} seguimientos")
            return jsonify(resultado), 200
        except Exception as e:
            logger.error(f"Error obteniendo seguimientos: {str(e)}", exc_info=True)
            return jsonify({'error': 'Error interno', 'details': str(e)}), 500

@app.route('/api/protocolos', methods=['GET'])
def get_protocolos():
    logger.info("Solicitud a /api/protocolos")
    protocolos = db.session.execute(db.select(Protocolo)).scalars().all()
    return jsonify([{'id_protocolo': p.id_protocolo, 'nombre': p.nombre, 'descripcion': p.descripcion} for p in protocolos])

@app.route('/api/criticidades', methods=['GET'])
def get_criticidades():
    logger.info("Solicitud a /api/criticidades")
    criticidades = db.session.execute(db.select(Criticidad)).scalars().all()
    return jsonify([{'id_criticidad': c.id_criticidad, 'nivel': c.nivel, 'descripcion': c.descripcion} for c in criticidades])

@app.route('/api/estados', methods=['GET'])
def get_estados():
    logger.info("Solicitud a /api/estados")
    estados = db.session.execute(db.select(Estado)).scalars().all()
    return jsonify([{'id_estado': e.id_estado, 'nombre': e.nombre, 'descripcion': e.descripcion} for e in estados])

@app.route('/api/usuarios', methods=['GET'])
@jwt_required()
def get_usuarios():
    current_user_id = get_jwt_identity()
    logger.info(f"Usuario autenticado consultando usuarios: {current_user_id}")
    usuarios = db.session.execute(db.select(Usuario)).scalars().all()
    resultado = [{'id_usuario': u.id_usuario, 'nombre': u.nombre, 'email': u.email, 'rol': u.rol} for u in usuarios]
    logger.info(f"Devolviendo {len(resultado)} usuarios")
    return jsonify(resultado), 200

@app.route('/api/verify-token', methods=['GET'])
@jwt_required(optional=True)
def verify_token():
    current_user_id = get_jwt_identity()
    logger.info(f"Verificando token - Usuario: {current_user_id or 'No autenticado'}")
    if not current_user_id:
        return jsonify({'valid': False, 'message': 'No autenticado, usa /login para obtener un token'}), 401
    user = db.session.get(Usuario, int(current_user_id))
    if user:
        return jsonify({'valid': True, 'user_id': current_user_id, 'nombre': user.nombre, 'email': user.email, 'rol': user.rol}), 200
    return jsonify({'valid': False, 'message': 'Usuario no encontrado'}), 404

def backup_db():
    backup_dir = os.path.join(basedir, 'backup')
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, f'sdgdrdc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
    try:
        shutil.copy(os.path.join(basedir, 'sdgdrdc.db'), backup_path)
        logger.info(f"Backup realizado en {backup_path}")
    except Exception as e:
        logger.error(f"Error en backup: {str(e)}")

def check_cerrada():
    vulnerabilidades = db.session.query(Vulnerabilidad).filter_by(id_estado=4).all()  # Resuelta
    for v in vulnerabilidades:
        ultimo_seguimiento = db.session.query(Seguimiento).filter_by(id_vulnerabilidad=v.id_vulnerabilidad).order_by(Seguimiento.fecha_accion.desc()).first()
        if ultimo_seguimiento and (datetime.utcnow() - ultimo_seguimiento.fecha_accion).days >= 7:
            v.id_estado = 5  # Cerrada
            db.session.commit()
            logger.info(f"Vulnerabilidad {v.id_vulnerabilidad} cerrada automáticamente")

if __name__ == '__main__':
    with app.app_context():
        inspector = inspect(db.engine)
        db_exists = os.path.exists(os.path.join(basedir, 'sdgdrdc.db'))
        tables = inspector.get_table_names()
        required_tables = ['usuarios', 'protocolos', 'criticidades', 'estados', 'vulnerabilidades', 'seguimientos']

        if not db_exists or not all(table in tables for table in required_tables):
            logger.info("Base de datos incompleta o no encontrada, creando...")
            db.create_all()
            if not db.session.query(Usuario).first():
                logger.info("Inicializando datos por defecto")
                try:
                    db.session.add(Usuario(nombre='Admin', email='admin@uniminuto.edu', contraseña=generate_password_hash('admin123'), rol='admin'))
                    db.session.flush()
                    protocolos = [Protocolo(nombre='SMB', descripcion='Server Message Block'),
                                Protocolo(nombre='TLS', descripcion='Transport Layer Security'),
                                Protocolo(nombre='SSL', descripcion='Secure Sockets Layer')]
                    criticidades = [Criticidad(nivel='Baja', descripcion='Impacto mínimo'),
                                  Criticidad(nivel='Media', descripcion='Impacto moderado'),
                                  Criticidad(nivel='Alta', descripcion='Impacto significativo'),
                                  Criticidad(nivel='Crítica', descripcion='Impacto crítico')]
                    estados = [Estado(nombre='Identificada', descripcion='Recién detectada'),
                             Estado(nombre='En análisis', descripcion='En evaluación'),
                             Estado(nombre='En remediación', descripcion='En corrección'),
                             Estado(nombre='Resuelta', descripcion='Solucionada'),
                             Estado(nombre='Cerrada', descripcion='Finalizada')]
                    db.session.bulk_save_objects(protocolos + criticidades + estados)
                    db.session.commit()
                    logger.info("Datos por defecto inicializados")
                except IntegrityError as e:
                    db.session.rollback()
                    logger.error(f"Error de integridad: {str(e)}")
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error inicializando: {str(e)}")
        else:
            logger.info("Base de datos existente detectada, no se reiniciarán los datos")
            # Asegurarse de que el usuario admin existe
            admin = db.session.execute(db.select(Usuario).filter_by(email='admin@uniminuto.edu')).scalar_one_or_none()
            if not admin:
                logger.info("Usuario admin no encontrado, creándolo...")
                db.session.add(Usuario(nombre='Admin', email='admin@uniminuto.edu', contraseña=generate_password_hash('admin123'), rol='admin'))
                db.session.commit()
                logger.info("Usuario admin creado")

    scheduler = BackgroundScheduler()
    scheduler.add_job(backup_db, 'cron', hour=0, minute=0)
    scheduler.add_job(check_cerrada, 'interval', hours=24)
    scheduler.start()

    app.run(debug=True, host='0.0.0.0', port=5000)