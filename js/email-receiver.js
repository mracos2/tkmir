// js/email-receiver.js
document.addEventListener('DOMContentLoaded', function() {
    const emailForm = document.getElementById('emailForm');

    emailForm.addEventListener('submit', async function(event) {
        event.preventDefault();

        const emailInput = document.getElementById('emailInput');
        const email = emailInput.value;

        if (!document.getElementById('termsCheckbox').checked) {
            alert('Пожалуйста, согласитесь на обработку данных');
            return;
        }

        try {
            const response = await fetch('http://localhost:5000/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `email=${email}`
            });

            const result = await response.json();

            if (response.ok) {
                alert(result.message);
                emailForm.reset();
            } else {
                alert(result.error);
            }
        } catch (error) {
            console.error('Ошибка:', error);
            alert('Ошибка соединения с сервером');
        }
    });
});