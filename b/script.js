const systemInfo = {
  userAgent: navigator.userAgent, // Информация о браузере и ОС
  language: navigator.language, // Язык браузера
  screenResolution: `${window.screen.width}x${window.screen.height}`, // Разрешение экрана
  maxTouchPoints: navigator.maxTouchPoints, // Число доступных точек касания (для мобильных устройств)
  platform: navigator.platform, // Платформа (например, 'Win32', 'MacIntel', 'Linux x86_64')
  cpuClass: navigator.cpuClass, // Тип процессора (устаревший, работает только в старых браузерах)
  deviceMemory: navigator.deviceMemory, // Оперативная память устройства (в ГБ), если доступна
  hardwareConcurrency: navigator.hardwareConcurrency, // Количество ядер процессора
  cookieEnabled: navigator.cookieEnabled, // Указание, включены ли cookies
  onlineStatus: navigator.onLine, // Сетевой статус: онлайн/оффлайн
  timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone, // Часовой пояс
  localStorage: 'localStorage' in window, // Поддержка localStorage
  sessionStorage: 'sessionStorage' in window, // Поддержка sessionStorage
  javaEnabled: navigator.javaEnabled(), // Наличие поддержки Java (обычно не используется)
  touchSupport: 'ontouchstart' in window || navigator.maxTouchPoints > 0, // Поддержка сенсорных экранов
  geolocation: 'geolocation' in navigator, // Поддержка геолокации
  screenColorDepth: window.screen.colorDepth, // Глубина цвета экрана
  browserVendor: navigator.vendor, // Производитель браузера (например, 'Google Inc.' для Chrome)
  browserVersion: navigator.appVersion, // Версия браузера
  devicePixelRatio: window.devicePixelRatio, // Масштаб экрана для ретина-устройств
};

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

