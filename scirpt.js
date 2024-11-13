// Получаем данные о браузере и системе
const systemInfo = {
    userAgent: navigator.userAgent, // Информация о браузере и ОС
    language: navigator.language, // Язык браузера
    screenResolution: `${window.screen.width}x${window.screen.height}`, // Разрешение экрана
};

// Отправка данных на сервер
fetch('http://188.243.207.170:9999/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(systemInfo),
})
.then(response => console.log("Data sent successfully"))
.catch(error => console.error("Error sending data:", error));
