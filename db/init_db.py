# db/init_db.py
import sqlite3
import os

def init_db():
    db_path = 'sdgdrdc.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    schema_path = os.path.join('db', 'schema.sql')
    if os.path.exists(schema_path):
        with open(schema_path, 'r', encoding='utf-8') as f:
            sql_script = f.read()
        
        commands = sql_script.split(';')
        for command in commands:
            command = command.strip()
            if command:
                try:
                    cursor.execute(command)
                except sqlite3.OperationalError as e:
                    if "already exists" not in str(e):
                        print(f"Error: {e}")
                    else:
                        print(f"Tabla ya existe, saltando: {command}")
                except sqlite3.IntegrityError as e:
                    print(f"Registro duplicado o error de integridad, saltando: {command} - {e}")
        conn.commit()
    else:
        print(f"Error: El archivo {schema_path} no existe.")
    conn.close()
    print("Base de datos procesada correctamente (tablas y datos existentes fueron ignorados).")

if __name__ == '__main__':
    init_db()