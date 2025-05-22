// Селекторы - Определяем DOM-элементы в начале скрипта для лучшей организации
const menuButton = document.getElementById('menuButton');
const overlay = document.getElementById('overlay');
const mobileMenu = document.getElementById('mobileMenu');
const navButtons = document.querySelectorAll('.nav-button'); // Перемещено сюда для наглядности

// --- Функциональность Меню ---
const menuTransitionDuration = 300; // Длительность анимации меню (должна совпадать с CSS)

// Функция для показа меню и оверлея
function showMenu() {
    mobileMenu.style.display = 'block'; // Изначально показываем (display: block) для анимации
    overlay.style.display = 'block';

    // Используем requestAnimationFrame для плавных переходов
    requestAnimationFrame(() => {
        overlay.style.opacity = '0.5';  // Показываем оверлей
        mobileMenu.style.transform = 'translateX(0)'; // Сдвигаем меню в видимую область
    });
}

// Функция для скрытия меню и оверлея
function hideMenu() {
    overlay.style.opacity = '0'; // Скрываем оверлей
    mobileMenu.style.transform = 'translateX(100%)'; // Сдвигаем меню за пределы экрана

    // Используем setTimeout, чтобы скрыть меню после завершения анимации
    setTimeout(() => {
        mobileMenu.style.display = 'none';
        overlay.style.display = 'none';
    }, menuTransitionDuration); // Длительность должна совпадать с CSS
}

// Обработчики событий для взаимодействия с меню
if (menuButton) { // Проверяем, существует ли элемент, чтобы избежать ошибок
    menuButton.addEventListener('click', showMenu);
}

if (overlay) { // Проверяем, существует ли элемент, чтобы избежать ошибок
    overlay.addEventListener('click', hideMenu);
}


// --- Настройка Размера Шрифта для Мобильного Меню ---
function setMenuFontSize() {
    const screenWidth = window.innerWidth;
    const fontSize = screenWidth / 30;

    // Вспомогательная функция для применения размера шрифта к нескольким элементам
    function applyFontSize(selector, size) {
        const elements = document.querySelectorAll(selector);
        elements.forEach(element => {
            element.style.fontSize = `${size}px`;
        });
    }

    applyFontSize('.mobile-menu .menu-buttons a', fontSize);
    applyFontSize('.mobile-menu .contact-info', fontSize);
}

// Начальная настройка и обработка изменения размера окна для шрифта
setMenuFontSize();
window.addEventListener('resize', setMenuFontSize);


// --- Стиль Кнопок (Тень) ---
function handleButtonInteraction(button) {
    button.addEventListener('mousedown', function () {
        this.style.boxShadow = 'inset 0 4px 20px 0px rgba(0, 0, 0, 0.25)'; // Добавляем внутреннюю тень при нажатии
    });

    button.addEventListener('mouseup', function () {
        this.style.boxShadow = ''; // Убираем тень при отпускании кнопки
    });

    button.addEventListener('mouseleave', function () {
        this.style.boxShadow = ''; // Убираем тень при уходе курсора с кнопки
    });
}

// Применяем стили кнопок ко всем элементам с классом 'nav-button'
navButtons.forEach(handleButtonInteraction);