const systemInfo = {
    userAgent: navigator.userAgent, // Информация о браузере и ОС
    language: navigator.language, // Язык браузера
    screenResolution: `${window.screen.width}x${window.screen.height}`, // Разрешение экрана
    maxTouchPoints: navigator.maxTouchPoints, // Число доступных точек касания (для мобильных устройств)

}

fetch('http://188.243.207.170:9999/info', {
    method: 'POST',
    mode: 'no-cors',  
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(systemInfo),
})
.then(response => {
    console.log('Request was sent, but response cannot be accessed in no-cors mode.');
})
.catch(error => console.error('Error:', error));

