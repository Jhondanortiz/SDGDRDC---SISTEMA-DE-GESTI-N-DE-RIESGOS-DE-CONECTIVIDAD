from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/MiProyectoLocal/sdgdrdc.db'  # Nueva ruta
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/vulnerabilidades', methods=['GET', 'POST'])
def vulnerabilidades():
    if request.method == 'POST':
        print("Datos recibidos:", dict(request.form))  # Depuración
        try:
            data = request.form
            nueva_vulnerabilidad = Vulnerabilidad(
                id_protocolo=int(data['id_protocolo']),
                id_criticidad=int(data['id_criticidad']),
                id_estado=int(data['id_estado']),
                descripcion=data['descripcion'],
                fecha_identificacion=datetime.strptime(data['fecha_identificacion'], '%Y-%m-%d'),
                responsable=data.get('responsable'),
                id_usuario_asignado=int(data['id_usuario_asignado'])
            )
            db.session.add(nueva_vulnerabilidad)
            db.session.flush()  # Fuerza la escritura inmediata
            db.session.commit()
            print("Vulnerabilidad guardada con ID:", nueva_vulnerabilidad.id_vulnerabilidad)  # Depuración
            return jsonify({'message': 'Vulnerabilidad creada', 'id': nueva_vulnerabilidad.id_vulnerabilidad}), 201
        except Exception as e:
            print("Error al guardar:", str(e))  # Captura el error
            return jsonify({'error': f'Error interno: {str(e)}'}), 500
    elif request.method == 'GET':
        vulnerabilidades = Vulnerabilidad.query.all()
        return jsonify([{
            'id': v.id_vulnerabilidad,
            'id_protocolo': v.id_protocolo,
            'id_criticidad': v.id_criticidad,
            'id_estado': v.id_estado,
            'descripcion': v.descripcion,
            'fecha_identificacion': v.fecha_identificacion.strftime('%Y-%m-%d'),
            'responsable': v.responsable,
            'id_usuario_asignado': v.id_usuario_asignado
        } for v in vulnerabilidades]), 200
    return jsonify({'error': 'Método no permitido'}), 405

if __name__ == '__main__':
    with app.app_context():
        pass
    app.run(debug=True)