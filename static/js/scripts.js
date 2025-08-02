// static/js/scripts.js

// Variables globales
let token = localStorage.getItem('token') || null;

// Verificar autenticación y validar token
async function verifyAuthentication() {
    if (!token) {
        alert('Por favor, inicie sesión primero.');
        window.location.href = '/'; // Redirigir a la página principal para login
        return false;
    }

    try {
        const response = await fetch('/api/protocolos', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok && response.status === 401) {
            alert('Sesión inválida o expirada. Por favor, inicie sesión de nuevo.');
            localStorage.removeItem('token');
            window.location.href = '/';
            return false;
        }
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
    if (!ctx) return; // Salir si no se encuentra el canvas

    if (!await verifyAuthentication()) return;

    try {
        const response = await fetch('/api/vulnerabilidades', {
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        if (!response.ok) throw new Error(`Error en la respuesta de la API: ${response.status}`);
        const vulnerabilities = await response.json();

        // Contar vulnerabilidades por protocolo
        const protocolCounts = vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.protocolo_nombre || 'Desconocido'] = (acc[vuln.protocolo_nombre || 'Desconocido'] || 0) + 1;
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
    } catch (error) {
        console.error('Error cargando el gráfico:', error);
        ctx.canvas.style.display = 'none'; // Ocultar canvas en caso de error
        alert('Error al cargar el gráfico. Verifique su sesión o los datos.');
    }
}

// Recargar gráfico
function refreshChart() {
    loadChart();
}

// Cargar gráfico al iniciar la página y manejar eventos
document.addEventListener('DOMContentLoaded', async function() {
    await loadChart();

    // Opcional: Escuchar eventos de actualización (por ejemplo, creación de vulnerabilidad)
    document.getElementById('vulnerabilidadForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        // Lógica de submit ya manejada en index.html, solo recargar gráfico
        setTimeout(refreshChart, 1000); // Esperar a que se complete la creación
    });
});

// Exportar funciones para uso en otros módulos (si es necesario)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { loadChart, refreshChart, verifyAuthentication };
}