// static/js/scripts.js

// Variables globales
let token = localStorage.getItem('token') || null;

// Verificar autenticación y validar token
async function verifyAuthentication() {
    if (!token) {
        console.log('No token found, redirecting to login');
        alert('Por favor, inicie sesión primero.');
        window.location.href = '/'; // Redirigir a la página principal para login
        return false;
    }

    try {
        console.log('Verificando autenticación con token:', token.substring(0, 10) + '...');
        const response = await fetch('/api/verify-token', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok && response.status === 401) {
            console.log('Token inválido, limpiando y redirigiendo');
            alert('Sesión inválida o expirada. Por favor, inicie sesión de nuevo.');
            localStorage.removeItem('token');
            window.location.href = '/';
            return false;
        }
        console.log('Autenticación verificada exitosamente');
        return true;
    } catch (error) {
        console.error('Error verificando autenticación:', error);
        alert('Error al verificar la sesión. Intente de nuevo.');
        return false;
    }
}

// Función para cargar y renderizar el gráfico
async function loadChart() {
    const ctx = document.getElementById('vulnerabilityChart')?.getContext('2d');
    if (!ctx) {
        console.warn('Canvas "vulnerabilityChart" no encontrado');
        return; // Salir si no se encuentra el canvas
    }

    if (!await verifyAuthentication()) return;

    try {
        console.log('Cargando datos para el gráfico con token:', token.substring(0, 10) + '...');
        const response = await fetch('/api/vulnerabilidades', {
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        console.log('API response status:', response.status);
        if (!response.ok) throw new Error(`Error en la respuesta de la API: ${response.status}`);
        const vulnerabilities = await response.json();
        console.log('Datos recibidos para el gráfico:', vulnerabilities.length, 'vulnerabilidades');

        if (!Array.isArray(vulnerabilities)) {
            throw new Error('Datos de vulnerabilidades no son un array válido');
        }

        // Contar vulnerabilidades por protocolo
        const protocolCounts = vulnerabilities.reduce((acc, vuln) => {
            const protocolo = vuln.protocolo_nombre || vuln.protocolo || 'Desconocido';
            acc[protocolo] = (acc[protocolo] || 0) + 1;
            return acc;
        }, {});

        // Generar colores dinámicos
        const colors = [
            '#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8', '#6f42c1', '#e83e8c',
            '#fd7e14', '#20c997', '#343a40'
        ];
        const backgroundColors = Object.keys(protocolCounts).map((_, i) => colors[i % colors.length]);
        const borderColors = backgroundColors.map(color => color.replace(/../, '00')); // Aclarar bordes

        // Configuración del gráfico
        const chartData = {
            type: 'bar',
            data: {
                labels: Object.keys(protocolCounts).length ? Object.keys(protocolCounts) : ['Sin datos'],
                datasets: [{
                    label: 'Vulnerabilidades por Protocolo',
                    data: Object.values(protocolCounts).length ? Object.values(protocolCounts) : [0],
                    backgroundColor: backgroundColors,
                    borderColor: borderColors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: { display: true, text: 'Número de Vulnerabilidades' }
                    },
                    x: {
                        title: { display: true, text: 'Protocolos' }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                }
            }
        };

        // Destruir gráfico anterior si existe para evitar duplicados
        if (window.vulnerabilityChart) {
            window.vulnerabilityChart.destroy();
        }

        // Crear nuevo gráfico
        window.vulnerabilityChart = new Chart(ctx, chartData);
        console.log('Gráfico renderizado exitosamente');
    } catch (error) {
        console.error('Error cargando el gráfico:', error);
        ctx.canvas.style.display = 'none'; // Ocultar canvas en caso de error
        showAlert('Error al cargar el gráfico. Verifique su sesión o los datos.', 'danger');
        if (error.message.includes('401')) {
            console.log('Unauthorized, clearing token and redirecting');
            localStorage.removeItem('token');
            window.location.href = '/';
        } else if (error.message.includes('404') || error.message.includes('500')) {
            showAlert('Error en el servidor. Contacte al administrador.', 'danger');
        }
    }
}

// Recargar gráfico
function refreshChart() {
    loadChart();
}

// Función para cargar Dashboard
async function loadDashboard() {
    if (!await verifyAuthentication()) return;

    try {
        const response = await fetch('/dashboard', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) {
            throw new Error(`Error al cargar Dashboard: ${response.status}`);
        }
        const html = await response.text();
        document.body.innerHTML = html;
        console.log('Dashboard cargado exitosamente');
    } catch (error) {
        console.error('Error cargando Dashboard:', error);
        alert('Error al cargar Dashboard. Verifique su sesión.');
    }
}

// Función para cargar Reports
async function loadReports() {
    if (!await verifyAuthentication()) return;

    try {
        const response = await fetch('/reports', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) {
            throw new Error(`Error al cargar Reports: ${response.status}`);
        }
        const html = await response.text();
        document.body.innerHTML = html;
        console.log('Reports cargado exitosamente');
    } catch (error) {
        console.error('Error cargando Reports:', error);
        alert('Error al cargar Reports. Verifique su sesión.');
    }
}

// Cargar gráfico al iniciar la página y manejar eventos
document.addEventListener('DOMContentLoaded', async function() {
    console.log('Page loaded, starting chart load');
    await loadChart();

    // Opcional: Escuchar eventos de actualización (por ejemplo, creación de vulnerabilidad)
    const form = document.getElementById('vulnerabilidadForm');
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            // Lógica de submit ya manejada en index.html, solo recargar gráfico
            setTimeout(refreshChart, 1000); // Esperar a que se complete la creación
        });
    }
});

// Exportar funciones para uso en otros módulos (si es necesario)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { loadChart, refreshChart, verifyAuthentication, loadDashboard, loadReports };
}