// public/js/scripts.js

document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form');

    if (form) {
        form.addEventListener('submit', function (event) {
            const time1 = document.getElementById('time1').value.trim();
            const time2 = document.getElementById('time2').value.trim();
            const data = document.getElementById('data').value.trim();
            const pontuacao = document.getElementById('pontuacao').value.trim();

            if (!time1 || !time2 || !data || !pontuacao) {
                alert('Por favor, preencha todos os campos.');
                event.preventDefault(); // Impede o envio do formulário
            } else if (!pontuacao.match(/^\d+-\d+$/)) {
                alert('A pontuação deve estar no formato "X-Y" (ex: 2-1).');
                event.preventDefault();
            }
        });
    }
});