from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sdgdrdc.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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

@app.route('/vulnerabilidades', methods=['POST'])
def create_vulnerabilidad():
    if request.method == 'POST':
        data = request.form
        nueva_vulnerabilidad = Vulnerabilidad(
            id_protocolo=int(data['id_protocolo']),
            id_criticidad=int(data['id_criticidad']),
            id_estado=int(data['id_estado']),
            descripcion=data['descripcion'],
            fecha_identificacion=datetime.strptime(data['fecha_identificacion'], '%Y-%m-%d'),
            responsable=data.get('responsable'),
            id_usuario_asignado=1  # Valor por defecto, ajusta según usuario logueado
        )
        db.session.add(nueva_vulnerabilidad)
        db.session.commit()
        return jsonify({'message': 'Vulnerabilidad creada', 'id': nueva_vulnerabilidad.id_vulnerabilidad}), 201
    return render_template('index.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Crea tablas faltantes sin sobrescribir
    app.run(debug=True)