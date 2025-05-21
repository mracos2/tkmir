        function adjustElectroEquipment() {
            const titleElement = document.getElementById('electroEquipmentTitle');
            if (!titleElement) return;

            const screenWidth = window.innerWidth;
            const originalText = "Электрооборудование";
            const replacedText = "Электро-оборудование";

            if ((screenWidth <= 633 && screenWidth >= 425) || (screenWidth <= 361 && screenWidth >= 320)) {
                if (titleElement.textContent === originalText) {
                    titleElement.textContent = replacedText;
                }
            } else {
                if (titleElement.textContent === replacedText) {
                    titleElement.textContent = originalText;
                }
            }
        }

        adjustElectroEquipment();
        window.addEventListener('resize', adjustElectroEquipment);