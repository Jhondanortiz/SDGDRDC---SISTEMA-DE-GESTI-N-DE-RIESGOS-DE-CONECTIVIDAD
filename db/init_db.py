from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# Obtener la ruta absoluta del directorio donde está este archivo
basedir = os.path.abspath(os.path.dirname(__file__))

# Configurar la base de datos para que se cree en la carpeta raíz del proyecto
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "sdgdrdc.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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
    id_protocolo = db.Column(db.Integer, db.ForeignKey('Protocolo.id_protocolo'))
    id_criticidad = db.Column(db.Integer, db.ForeignKey('Criticidad.id_criticidad'))
    id_estado = db.Column(db.Integer, db.ForeignKey('Estado.id_estado'))
    descripcion = db.Column(db.Text, nullable=False)
    fecha_identificacion = db.Column(db.Date, nullable=False)
    responsable = db.Column(db.Text)
    id_usuario_asignado = db.Column(db.Integer, db.ForeignKey('Usuario.id_usuario'))

def init_db():
    with app.app_context():
        # Crear todas las tablas si no existen
        db.create_all()
        
        # Mostrar la ubicación donde se creará la base de datos
        db_path = os.path.join(basedir, "sdgdrdc.db")
        print(f"Base de datos ubicada en: {db_path}")

        # Intentar ejecutar el esquema desde schema.sql si existe
        schema_path = os.path.join(basedir, 'schema.sql')
        if os.path.exists(schema_path):
            with open(schema_path, 'r', encoding='utf-8') as f:
                sql_script = f.read()
            commands = [cmd.strip() for cmd in sql_script.split(';') if cmd.strip()]
            for command in commands:
                try:
                    db.session.execute(command)
                except Exception as e:
                    print(f"Advertencia: {e} - Comando omitido: {command}")
            db.session.commit()
        else:
            print(f"Advertencia: El archivo schema.sql no se encontró en {schema_path}. Usando solo creación automática.")

        # Poblar datos iniciales si no existen
        if not Protocolo.query.first():
            db.session.add_all([
                Protocolo(id_protocolo=1, nombre="SMB", descripcion="Server Message Block"),
                Protocolo(id_protocolo=2, nombre="TLS", descripcion="Transport Layer Security"),
                Protocolo(id_protocolo=3, nombre="SSL", descripcion="Secure Sockets Layer")
            ])
        if not Criticidad.query.first():
            db.session.add_all([
                Criticidad(id_criticidad=1, nivel="Baja", descripcion="Bajo impacto"),
                Criticidad(id_criticidad=2, nivel="Media", descripcion="Impacto moderado"),
                Criticidad(id_criticidad=3, nivel="Alta", descripcion="Alto impacto"),
                Criticidad(id_criticidad=4, nivel="Crítica", descripcion="Impacto crítico")
            ])
        if not Estado.query.first():
            db.session.add_all([
                Estado(id_estado=1, nombre="Identificada", descripcion="Recién detectada"),
                Estado(id_estado=2, nombre="En análisis", descripcion="En evaluación"),
                Estado(id_estado=3, nombre="En remediación", descripcion="En proceso de corrección"),
                Estado(id_estado=4, nombre="Resuelta", descripcion="Solucionada"),
                Estado(id_estado=5, nombre="Cerrada", descripcion="Finalizada")
            ])
        if not Usuario.query.first():
            db.session.add(Usuario(id_usuario=1, nombre="Admin", email="admin@uniminuto.edu", contraseña="admin123", rol="Administrador"))
        
        # Confirmar los cambios antes de insertar vulnerabilidades
        db.session.commit()
        
        # Poblar datos iniciales de vulnerabilidades si no existen
        if not Vulnerabilidad.query.first():
            from datetime import date
            db.session.add_all([
                Vulnerabilidad(
                    id_protocolo=1,  # SMB
                    id_criticidad=4,  # Crítica
                    id_estado=1,  # Identificada
                    descripcion="Vulnerabilidad crítica en protocolo SMB que permite acceso no autorizado",
                    fecha_identificacion=date(2024, 1, 15),
                    responsable="Equipo de Seguridad",
                    id_usuario_asignado=1
                ),
                Vulnerabilidad(
                    id_protocolo=2,  # TLS
                    id_criticidad=3,  # Alta
                    id_estado=2,  # En análisis
                    descripcion="Configuración débil de cifrado en TLS versión 1.0",
                    fecha_identificacion=date(2024, 2, 10),
                    responsable="Administrador de Red",
                    id_usuario_asignado=1
                ),
                Vulnerabilidad(
                    id_protocolo=3,  # SSL
                    id_criticidad=2,  # Media
                    id_estado=3,  # En remediación
                    descripcion="Certificado SSL próximo a vencer en 30 días",
                    fecha_identificacion=date(2024, 3, 5),
                    responsable="Equipo de Infraestructura",
                    id_usuario_asignado=1
                ),
                Vulnerabilidad(
                    id_protocolo=1,  # SMB
                    id_criticidad=1,  # Baja
                    id_estado=4,  # Resuelta
                    descripcion="Configuración de shares SMB sin autenticación adecuada",
                    fecha_identificacion=date(2024, 1, 20),
                    responsable="Administrador de Sistemas",
                    id_usuario_asignado=1
                ),
                Vulnerabilidad(
                    id_protocolo=2,  # TLS
                    id_criticidad=3,  # Alta
                    id_estado=5,  # Cerrada
                    descripcion="Vulnerabilidad en handshake TLS corregida mediante actualización",
                    fecha_identificacion=date(2024, 2, 28),
                    responsable="DevOps Team",
                    id_usuario_asignado=1
                )
            ])
        
        db.session.commit()
        print("Base de datos inicializada con éxito.")

if __name__ == '__main__':
    init_db()