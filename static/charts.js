const ctx = document.getElementById('trafficChart');

new Chart(ctx, {
  type: 'pie',
  data: {
    labels: ['Normal Traffic', 'Suspicious Traffic'],
    datasets: [{
      data: [75, 25],
      backgroundColor: ['#2ecc71', '#e74c3c']
    }]
  }
});
