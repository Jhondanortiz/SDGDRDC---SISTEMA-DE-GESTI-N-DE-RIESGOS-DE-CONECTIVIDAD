// static/js/scripts.js
const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
const chart = {
  type: 'bar',
  data: {
    labels: ['SMB', 'TLS', 'SSL'],
    datasets: [{
      label: 'Vulnerabilidades por Protocolo',
      data: [10, 15, 8], // Ejemplo de datos
      backgroundColor: ['#007bff', '#28a745', '#dc3545'],
      borderColor: ['#0056b3', '#218838', '#c82333'],
      borderWidth: 1
    }]
  },
  options: {
    scales: {
      y: {
        beginAtZero: true
      }
    }
  }
};
new Chart(ctx, chart);