// ----------------------------------------------------------------
// Константы и переменные
// ----------------------------------------------------------------

// Название и версия базы для IndexedDB
const DB_NAME = 'SecurePasswordManagerDB';
const DB_VERSION = 1;

// Названия "таблиц" (object stores)
const KEY_STORE_NAME = 'encryptionKeyStore';
const PASSWORD_STORE_NAME = 'passwords';

// Глобальная переменная для сырого байтового ключа шифрования (master key)
let rawMasterKey = null;


// ----------------------------------------------------------------
// Функции для работы с IndexedDB
// ----------------------------------------------------------------

/**
 * Открытие (или создание) базы данных IndexedDB.
 * Возвращает Promise, который резолвится в объект базы данных (IDBDatabase).
 */
function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    // Срабатывает при первом создании/обновлении структуры базы
    request.onupgradeneeded = (event) => {
      const db = event.target.result;

      // Хранилище ключа
      if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
        db.createObjectStore(KEY_STORE_NAME, { keyPath: 'id' });
      }

      // Хранилище паролей
      if (!db.objectStoreNames.contains(PASSWORD_STORE_NAME)) {
        db.createObjectStore(PASSWORD_STORE_NAME, {
          keyPath: 'id',
          autoIncrement: true
        });
      }
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

/**
 * Получение мастер-ключа (rawMasterKey) из IndexedDB (или null, если не найден).
 */
async function getMasterKeyFromDB() {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(KEY_STORE_NAME, 'readonly');
    const store = transaction.objectStore(KEY_STORE_NAME);
    // Храним под фиксированным ключом id=1
    const getRequest = store.get(1);

    getRequest.onsuccess = () => {
      // Если записи нет, вернёт undefined
      resolve(getRequest.result?.rawKey || null);
    };

    getRequest.onerror = () => {
      reject(getRequest.error);
    };
  });
}

/**
 * Сохранение мастер-ключа (rawMasterKey) в IndexedDB.
 */
async function saveMasterKeyToDB(rawKey) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(KEY_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(KEY_STORE_NAME);
    const putRequest = store.put({ id: 1, rawKey });

    putRequest.onsuccess = () => {
      resolve();
    };

    putRequest.onerror = () => {
      reject(putRequest.error);
    };
  });
}

/**
 * Сохранение зашифрованного пароля в IndexedDB.
 * @param {Object} obj - Объект с полями: website, username, iv, ciphertext
 */
async function saveEncryptedPasswordToDB({ website, username, iv, ciphertext }) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(PASSWORD_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(PASSWORD_STORE_NAME);
    // Вставляем запись (autoIncrement создаст id)
    const request = store.add({ website, username, iv, ciphertext });

    request.onsuccess = () => {
      resolve();
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

/**
 * Получение всех сохранённых паролей из IndexedDB.
 */
async function getAllPasswords() {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(PASSWORD_STORE_NAME, 'readonly');
    const store = transaction.objectStore(PASSWORD_STORE_NAME);
    const request = store.getAll();

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

/**
 * Удаление записи о пароле по его ID.
 */
async function deletePasswordById(id) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(PASSWORD_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(PASSWORD_STORE_NAME);
    const request = store.delete(id);

    request.onsuccess = () => {
      resolve();
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}


// ----------------------------------------------------------------
// Функции шифрования и расшифрования (AES-GCM)
// ----------------------------------------------------------------

/**
 * Генерация нового мастер-ключа (AES-GCM, 256 бит).
 * Возвращается сырой ключ (ArrayBuffer).
 */
async function generateMasterKey() {
  const key = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true,  // Ключ можно экспортировать
    ['encrypt', 'decrypt']
  );
  return crypto.subtle.exportKey('raw', key); // ArrayBuffer
}

/**
 * Импорт сырого ключа (ArrayBuffer) в объект CryptoKey.
 */
async function importKey(rawKey) {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM' },
    false, // Не нужно заново экспортировать
    ['encrypt', 'decrypt']
  );
}

/**
 * Шифрование пароля (plainTextPassword) с помощью AES-GCM.
 * Возвращает объект { iv, ciphertext } в виде массивов байт.
 */
async function encryptPassword(plainTextPassword) {
  const key = await importKey(rawMasterKey);

  // Генерируем IV (12 байт)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    key,
    new TextEncoder().encode(plainTextPassword)
  );

  return {
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(encryptedBuffer))
  };
}

/**
 * Расшифровка (AES-GCM).
 * На вход принимает { iv, ciphertext } в виде массивов.
 * Возвращает расшифрованную строку.
 */
async function decryptPassword(encryptedData) {
  const key = await importKey(rawMasterKey);

  const iv = new Uint8Array(encryptedData.iv);
  const ciphertext = new Uint8Array(encryptedData.ciphertext);

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv
    },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decryptedBuffer);
}


// ----------------------------------------------------------------
// Генератор криптографически безопасных паролей
// ----------------------------------------------------------------

/**
 * Генерирует пароль заданной длины с выбранными наборами символов.
 * Используется window.crypto.getRandomValues для генерации байт.
 */
function generateSecurePassword(options) {
  const {
    length,
    useUppercase,
    useLowercase,
    useDigits,
    useSymbols
  } = options;

  // Наборы символов
  const uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
  const digitChars = '0123456789';
  // Можно дополнительно расширить набор спецсимволов
  const symbolChars = '!@#$%^&*()-_=+[]{}|;:,.<>?/';

  // Собираем общий пул символов
  let charPool = '';
  if (useUppercase) charPool += uppercaseChars;
  if (useLowercase) charPool += lowercaseChars;
  if (useDigits)    charPool += digitChars;
  if (useSymbols)   charPool += symbolChars;

  if (!charPool) {
    // Если пользователь снял все галочки
    throw new Error('Не выбрано ни одного набора символов для пароля!');
  }

  // Генерируем массив случайных байт
  const randomValues = new Uint8Array(length);
  window.crypto.getRandomValues(randomValues);

  // Собираем пароль
  let result = '';
  for (let i = 0; i < length; i++) {
    // Берём байт по модулю длины набора символов
    const randomIndex = randomValues[i] % charPool.length;
    result += charPool[randomIndex];
  }

  return result;
}


// ----------------------------------------------------------------
// Логика интерфейса и событий
// ----------------------------------------------------------------

/**
 * Обновление списка паролей в таблице.
 */
async function refreshPasswordList() {
  const passwordTableBody = document.getElementById('passwordTableBody');
  passwordTableBody.innerHTML = ''; // очистка текущих строк

  const passwords = await getAllPasswords();

  for (const entry of passwords) {
    const row = document.createElement('tr');

    // Столбец: Сайт
    const websiteCell = document.createElement('td');
    websiteCell.textContent = entry.website;
    row.appendChild(websiteCell);

    // Столбец: Имя пользователя
    const usernameCell = document.createElement('td');
    usernameCell.textContent = entry.username;
    row.appendChild(usernameCell);

    // Столбец: Кнопка "Показать пароль"
    const passwordCell = document.createElement('td');
    const viewButton = document.createElement('button');
    viewButton.textContent = 'Показать';
    viewButton.classList.add('view-btn');
    viewButton.addEventListener('click', async () => {
      try {
        const decrypted = await decryptPassword({
          iv: entry.iv,
          ciphertext: entry.ciphertext
        });
        alert(`Пароль: ${decrypted}`);
      } catch (err) {
        console.error('Ошибка при расшифровке:', err);
        alert('Не удалось расшифровать пароль.');
      }
    });
    passwordCell.appendChild(viewButton);
    row.appendChild(passwordCell);

    // Столбец: Кнопка "Удалить"
    const actionCell = document.createElement('td');
    const deleteButton = document.createElement('button');
    deleteButton.textContent = 'Удалить';
    deleteButton.classList.add('delete-btn');
    deleteButton.addEventListener('click', async () => {
      await deletePasswordById(entry.id);
      await refreshPasswordList();
    });
    actionCell.appendChild(deleteButton);
    row.appendChild(actionCell);

    // Добавляем строку в таблицу
    passwordTableBody.appendChild(row);
  }
}

/**
 * Обработчик кнопки "Сгенерировать" (генерация пароля по заданным параметрам).
 */
function handleGeneratePassword() {
  const lengthInput = document.getElementById('length');
  const useUppercaseInput = document.getElementById('useUppercase');
  const useLowercaseInput = document.getElementById('useLowercase');
  const useDigitsInput = document.getElementById('useDigits');
  const useSymbolsInput = document.getElementById('useSymbols');
  const generatedPasswordInput = document.getElementById('generatedPassword');

  try {
    const length = parseInt(lengthInput.value, 10);
    const generatedPass = generateSecurePassword({
      length,
      useUppercase: useUppercaseInput.checked,
      useLowercase: useLowercaseInput.checked,
      useDigits: useDigitsInput.checked,
      useSymbols: useSymbolsInput.checked
    });
    // Выводим результат в поле "Сгенерированный пароль"
    generatedPasswordInput.value = generatedPass;
  } catch (error) {
    alert(error.message);
  }
}

/**
 * Обработчик формы добавления пароля в менеджер.
 */
async function handleAddPasswordSubmit(event) {
  event.preventDefault();

  const websiteInput = document.getElementById('website');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');

  const website = websiteInput.value.trim();
  const username = usernameInput.value.trim();
  const plainPassword = passwordInput.value;

  // Проверка заполнения
  if (!website || !username || !plainPassword) {
    alert('Пожалуйста, заполните все поля (сайт, имя пользователя, пароль).');
    return;
  }

  try {
    // Шифруем пароль
    const encrypted = await encryptPassword(plainPassword);

    // Сохраняем в IndexedDB
    await saveEncryptedPasswordToDB({
      website,
      username,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext
    });

    // Очищаем поля
    websiteInput.value = '';
    usernameInput.value = '';
    passwordInput.value = '';

    // Обновляем список паролей
    await refreshPasswordList();
  } catch (err) {
    console.error('Ошибка при шифровании/сохранении:', err);
    alert('Не удалось сохранить пароль.');
  }
}

/**
 * Функция инициализации приложения.
 * Вызывается после загрузки DOM (DOMContentLoaded).
 */
async function initApp() {
  try {
    // 1. Проверяем, есть ли уже в IndexedDB сохранённый мастер-ключ.
    let storedKey = await getMasterKeyFromDB();
    if (!storedKey) {
      // Если ключа нет, генерируем новый
      storedKey = await generateMasterKey();
      // Сохраняем в IndexedDB
      await saveMasterKeyToDB(storedKey);
    }
    // Запоминаем в глобальной переменной
    rawMasterKey = storedKey;

    // 2. Обновляем список паролей
    await refreshPasswordList();

    // 3. Назначаем обработчики
    // Генерация
    const generateBtn = document.getElementById('generateBtn');
    generateBtn.addEventListener('click', handleGeneratePassword);

    // Сохранение нового пароля
    const passwordForm = document.getElementById('passwordForm');
    passwordForm.addEventListener('submit', handleAddPasswordSubmit);

  } catch (error) {
    console.error('Ошибка инициализации приложения:', error);
    alert('Ошибка инициализации. Проверьте консоль разработчика.');
  }
}

// Запускаем initApp после загрузки страницы
window.addEventListener('DOMContentLoaded', initApp);
