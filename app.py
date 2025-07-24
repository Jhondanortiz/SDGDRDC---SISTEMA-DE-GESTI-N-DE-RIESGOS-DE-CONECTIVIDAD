# app.py
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sdgdrdc.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Modelos de la base de datos
class Protocolo(db.Model):
    id_protocolo = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    descripcion = db.Column(db.Text)

class Vulnerabilidad(db.Model):
    id_vulnerabilidad = db.Column(db.Integer, primary_key=True)
    id_protocolo = db.Column(db.Integer, db.ForeignKey('protocolo.id_protocolo'))
    id_criticidad = db.Column(db.Integer)
    id_estado = db.Column(db.Integer)
    descripcion = db.Column(db.Text, nullable=False)
    fecha_identificacion = db.Column(db.Date, nullable=False)
    responsable = db.Column(db.String(100))
    id_usuario_asignado = db.Column(db.Integer)

# Ejemplo de endpoint REST
@app.route('/vulnerabilidades', methods=['POST'])
def create_vulnerabilidad():
    data = request.get_json()
    nueva_vulnerabilidad = Vulnerabilidad(
        id_protocolo=data['id_protocolo'],
        id_criticidad=data['id_criticidad'],
        id_estado=data['id_estado'],
        descripcion=data['descripcion'],
        fecha_identificacion=datetime.strptime(data['fecha_identificacion'], '%Y-%m-%d'),
        responsable=data.get('responsable'),
        id_usuario_asignado=data.get('id_usuario_asignado')
    )
    db.session.add(nueva_vulnerabilidad)
    db.session.commit()
    return jsonify({'message': 'Vulnerabilidad creada', 'id': nueva_vulnerabilidad.id_vulnerabilidad}), 201

@app.route('/vulnerabilidades', methods=['GET'])
def get_vulnerabilidades():
    vulnerabilidades = Vulnerabilidad.query.all()
    return jsonify([{
        'id_vulnerabilidad': v.id_vulnerabilidad,
        'id_protocolo': v.id_protocolo,
        'descripcion': v.descripcion,
        'fecha_identificacion': v.fecha_identificacion.isoformat()
    } for v in vulnerabilidades])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crea las tablas si no existen
    app.run(debug=True)