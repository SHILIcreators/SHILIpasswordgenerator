// ---------------------
// Константы и переменные
// ---------------------

const DB_NAME = 'SecurePasswordManagerDB';
const DB_VERSION = 1;
const KEY_STORE_NAME = 'encryptionKeyStore';
const PASSWORD_STORE_NAME = 'passwords';

// Храним в этой переменной (в оперативной памяти) байтовый массив, 
// представляющий ключ, чтобы не загружать его из IndexedDB каждый раз.
let rawMasterKey = null;

// ---------------------
// Функция инициализации IndexedDB
// ---------------------
function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;

      // Создаём хранилище для ключа (ключ - фиксированный id = 1, например)
      if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
        const keyStore = db.createObjectStore(KEY_STORE_NAME, { keyPath: 'id' });
      }

      // Создаём хранилище для паролей
      if (!db.objectStoreNames.contains(PASSWORD_STORE_NAME)) {
        const passwordStore = db.createObjectStore(PASSWORD_STORE_NAME, {
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

// ---------------------
// Функция получения ключа из IndexedDB
// ---------------------
async function getMasterKeyFromDB() {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(KEY_STORE_NAME, 'readonly');
    const store = transaction.objectStore(KEY_STORE_NAME);
    const getRequest = store.get(1);

    getRequest.onsuccess = () => {
      resolve(getRequest.result?.rawKey || null);
    };

    getRequest.onerror = () => {
      reject(getRequest.error);
    };
  });
}

// ---------------------
// Функция сохранения ключа в IndexedDB
// ---------------------
async function saveMasterKeyToDB(rawKey) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(KEY_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(KEY_STORE_NAME);
    // Сохраняем запись с id = 1 (можно хранить как угодно, тут для примера фиксируем)
    const putRequest = store.put({ id: 1, rawKey });

    putRequest.onsuccess = () => {
      resolve();
    };

    putRequest.onerror = () => {
      reject(putRequest.error);
    };
  });
}

// ---------------------
// Генерация нового ключа (AES-GCM 256 бит)
// ---------------------
async function generateMasterKey() {
  const key = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true, // Экспортируемый ключ
    ['encrypt', 'decrypt']
  );
  // Экспортируем его в виде сырых байт
  return crypto.subtle.exportKey('raw', key);
}

// ---------------------
// Импорт сырого байтового ключа в CryptoKey
// ---------------------
async function importKey(rawKey) {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    {
      name: 'AES-GCM'
    },
    false,
    ['encrypt', 'decrypt']
  );
}

// ---------------------
// Шифрование пароля с помощью AES-GCM
// ---------------------
async function encryptPassword(plainTextPassword) {
  const key = await importKey(rawMasterKey);

  // Генерируем IV (инициализационный вектор) для AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Шифруем
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    new TextEncoder().encode(plainTextPassword)
  );

  // Получаем зашифрованные данные в виде ArrayBuffer
  // Возвращаем объект с зашифрованным буфером и IV
  return {
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(encryptedBuffer))
  };
}

// ---------------------
// Расшифровка пароля с помощью AES-GCM
// ---------------------
async function decryptPassword(encryptedData) {
  const key = await importKey(rawMasterKey);

  const iv = new Uint8Array(encryptedData.iv);
  const ciphertext = new Uint8Array(encryptedData.ciphertext);

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decryptedBuffer);
}

// ---------------------
// Сохранение зашифрованного пароля в IndexedDB
// ---------------------
async function saveEncryptedPasswordToDB({ website, username, iv, ciphertext }) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(PASSWORD_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(PASSWORD_STORE_NAME);
    const request = store.add({ website, username, iv, ciphertext });

    request.onsuccess = () => {
      resolve();
    };

    request.onerror = () => {
      reject(request.error);
    };
  });
}

// ---------------------
// Получение всех паролей из IndexedDB
// ---------------------
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

// ---------------------
// Удаление пароля из IndexedDB по ID
// ---------------------
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

// ---------------------
// Функция для обновления таблицы паролей на экране
// ---------------------
async function refreshPasswordList() {
  const passwordTableBody = document.getElementById('passwordTableBody');
  passwordTableBody.innerHTML = ''; // Очищаем таблицу

  const passwords = await getAllPasswords();

  // Отображаем каждую запись в виде строки таблицы
  for (const entry of passwords) {
    const row = document.createElement('tr');

    const websiteCell = document.createElement('td');
    websiteCell.textContent = entry.website;
    row.appendChild(websiteCell);

    const usernameCell = document.createElement('td');
    usernameCell.textContent = entry.username;
    row.appendChild(usernameCell);

    // Ячейка с кнопкой "Показать пароль"
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
      } catch (e) {
        console.error('Ошибка при расшифровке:', e);
        alert('Не удалось расшифровать пароль.');
      }
    });
    passwordCell.appendChild(viewButton);
    row.appendChild(passwordCell);

    // Ячейка с кнопкой "Удалить"
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
    passwordTableBody.appendChild(row);
  }
}

// ---------------------
// Обработчик отправки формы
// ---------------------
async function handleFormSubmit(event) {
  event.preventDefault();

  const websiteInput = document.getElementById('website');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');

  const website = websiteInput.value.trim();
  const username = usernameInput.value.trim();
  const plainPassword = passwordInput.value;

  if (!website || !username || !plainPassword) {
    alert('Пожалуйста, заполните все поля.');
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

    // Очищаем поля формы
    websiteInput.value = '';
    usernameInput.value = '';
    passwordInput.value = '';

    // Обновляем список
    await refreshPasswordList();
  } catch (error) {
    console.error('Ошибка при шифровании или сохранении:', error);
    alert('Не удалось сохранить пароль.');
  }
}

// ---------------------
// Основная инициализация приложения
// ---------------------
window.addEventListener('DOMContentLoaded', async () => {
  try {
    // Проверяем, есть ли уже сгенерированный ключ
    let storedKey = await getMasterKeyFromDB();
    
    if (!storedKey) {
      // Если нет - генерируем новый
      storedKey = await generateMasterKey();
      // Сохраняем в IndexedDB
      await saveMasterKeyToDB(storedKey);
    }

    // Сохраняем ключ в глобальной переменной (rawMasterKey)
    rawMasterKey = storedKey;

    // Обновляем список паролей
    await refreshPasswordList();

    // Добавляем обработчик события для формы
    const passwordForm = document.getElementById('passwordForm');
    passwordForm.addEventListener('submit', handleFormSubmit);

  } catch (error) {
    console.error('Ошибка инициализации приложения:', error);
    alert('Ошибка инициализации приложения. Проверьте консоль разработчика.');
  }
});