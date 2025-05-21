// js/feedback-receiver.js
document.addEventListener('DOMContentLoaded', function() {
    const feedbackForm = document.getElementById('feedbackForm');

    feedbackForm.addEventListener('submit', async function(event) {
        event.preventDefault();

        const formData = new FormData(feedbackForm);
        const data = {
            name: formData.get('name'),
            phone: formData.get('phone'),
            email: formData.get('email'),
            message: formData.get('message')
        };

        if (!document.getElementById('terms').checked) {
            alert('Пожалуйста, согласитесь на обработку данных');
            return;
        }

        try {
            const response = await fetch('http://localhost:5000/submit-feedback', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams(data)
            });

            const result = await response.json();

            if (response.ok) {
                alert(result.message);
                feedbackForm.reset();
            } else {
                alert(result.error);
            }
        } catch (error) {
            console.error('Ошибка:', error);
            alert('Ошибка соединения с сервером');
        }
    });
});