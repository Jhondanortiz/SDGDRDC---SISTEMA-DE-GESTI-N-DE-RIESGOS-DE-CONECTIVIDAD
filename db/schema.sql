-- db/schema.sql
-- Tabla Protocolo
CREATE TABLE Protocolo (
    id_protocolo INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL, -- SMB, TLS, SSL
    descripcion TEXT
);

-- Tabla Criticidad
CREATE TABLE Criticidad (
    id_criticidad INTEGER PRIMARY KEY AUTOINCREMENT,
    nivel TEXT NOT NULL, -- Baja, Media, Alta, Crítica
    descripcion TEXT
);

-- Tabla Estado
CREATE TABLE Estado (
    id_estado INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL, -- Identificada, En análisis, En remediación, Resuelta, Cerrada
    descripcion TEXT
);

-- Tabla Usuario
CREATE TABLE Usuario (
    id_usuario INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    contraseña TEXT NOT NULL,
    rol TEXT NOT NULL -- Admin, Analista
);

-- Tabla Vulnerabilidad
CREATE TABLE Vulnerabilidad (
    id_vulnerabilidad INTEGER PRIMARY KEY AUTOINCREMENT,
    id_protocolo INTEGER,
    id_criticidad INTEGER,
    id_estado INTEGER,
    descripcion TEXT NOT NULL,
    fecha_identificacion DATE NOT NULL,
    responsable TEXT,
    id_usuario_asignado INTEGER,
    FOREIGN KEY (id_protocolo) REFERENCES Protocolo(id_protocolo),
    FOREIGN KEY (id_criticidad) REFERENCES Criticidad(id_criticidad),
    FOREIGN KEY (id_estado) REFERENCES Estado(id_estado),
    FOREIGN KEY (id_usuario_asignado) REFERENCES Usuario(id_usuario)
);

-- Tabla Seguimiento
CREATE TABLE Seguimiento (
    id_seguimiento INTEGER PRIMARY KEY AUTOINCREMENT,
    id_vulnerabilidad INTEGER,
    fecha_accion DATE NOT NULL,
    accion TEXT NOT NULL,
    id_usuario INTEGER,
    comentarios TEXT,
    FOREIGN KEY (id_vulnerabilidad) REFERENCES Vulnerabilidad(id_vulnerabilidad),
    FOREIGN KEY (id_usuario) REFERENCES Usuario(id_usuario)
);

-- Tabla Reporte
CREATE TABLE Reporte (
    id_reporte INTEGER PRIMARY KEY AUTOINCREMENT,
    id_vulnerabilidad INTEGER,
    fecha_generacion DATE NOT NULL,
    formato TEXT NOT NULL, -- PDF, Excel
    contenido TEXT,
    FOREIGN KEY (id_vulnerabilidad) REFERENCES Vulnerabilidad(id_vulnerabilidad)
);

-- Tabla BaseConocimiento
CREATE TABLE BaseConocimiento (
    id_conocimiento INTEGER PRIMARY KEY AUTOINCREMENT,
    id_vulnerabilidad INTEGER,
    id_protocolo INTEGER,
    procedimiento TEXT NOT NULL,
    referencia_cve TEXT,
    referencia_nist TEXT,
    FOREIGN KEY (id_vulnerabilidad) REFERENCES Vulnerabilidad(id_vulnerabilidad),
    FOREIGN KEY (id_protocolo) REFERENCES Protocolo(id_protocolo)
);

-- Tabla Metrica
CREATE TABLE Metrica (
    id_metrica INTEGER PRIMARY KEY AUTOINCREMENT,
    id_vulnerabilidad INTEGER,
    nombre_metrica TEXT NOT NULL,
    valor REAL NOT NULL,
    fecha_actualizacion DATE NOT NULL,
    FOREIGN KEY (id_vulnerabilidad) REFERENCES Vulnerabilidad(id_vulnerabilidad)
);

-- Datos iniciales de prueba
INSERT INTO Protocolo (nombre, descripcion) VALUES
    ('SMB', 'Protocolo de intercambio de archivos'),
    ('TLS', 'Protocolo de seguridad de transporte'),
    ('SSL', 'Protocolo de capa de sockets seguros');

INSERT INTO Criticidad (nivel, descripcion) VALUES
    ('Baja', 'Impacto mínimo'),
    ('Media', 'Impacto moderado'),
    ('Alta', 'Impacto significativo'),
    ('Crítica', 'Impacto crítico');

INSERT INTO Estado (nombre, descripcion) VALUES
    ('Identificada', 'Vulnerabilidad detectada'),
    ('En análisis', 'En proceso de evaluación'),
    ('En remediación', 'En proceso de corrección'),
    ('Resuelta', 'Vulnerabilidad corregida'),
    ('Cerrada', 'Caso cerrado');

INSERT INTO Usuario (nombre, email, contraseña, rol) VALUES
    ('Admin', 'admin@bancoagrario.com', 'hashed_password', 'Admin');