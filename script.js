
const DB_NAME = 'SecurePasswordManagerDB';
const DB_VERSION = 1;
const KEY_STORE_NAME = 'encryptionKeyStore';
const PASSWORD_STORE_NAME = 'passwords';
let rawMasterKey = null;
function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;

      if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
        db.createObjectStore(KEY_STORE_NAME, { keyPath: 'id' });
      }


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


async function getMasterKeyFromDB() {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(KEY_STORE_NAME, 'readonly');
    const store = transaction.objectStore(KEY_STORE_NAME);
    // Храним под фиксированным ключом id=1
    const getRequest = store.get(1);

    getRequest.onsuccess = () => {
      
      resolve(getRequest.result?.rawKey || null);
    };

    getRequest.onerror = () => {
      reject(getRequest.error);
    };
  });
}


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



async function generateMasterKey() {
  const key = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true,  // Ключ можно экспортировать
    ['encrypt', 'decrypt']
  );
  return crypto.subtle.exportKey('raw', key); 
}


async function importKey(rawKey) {
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-GCM' },
    false, 
    ['encrypt', 'decrypt']
  );
}


async function encryptPassword(plainTextPassword) {
  const key = await importKey(rawMasterKey);

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



function generateSecurePassword(options) {
  const {
    length,
    useUppercase,
    useLowercase,
    useDigits,
    useSymbols
  } = options;

  const uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
  const digitChars = '0123456789';
  
  const symbolChars = '!@#$%^&*()-_=+[]{}|;:,.<>?/';

  let charPool = '';
  if (useUppercase) charPool += uppercaseChars;
  if (useLowercase) charPool += lowercaseChars;
  if (useDigits)    charPool += digitChars;
  if (useSymbols)   charPool += symbolChars;

  if (!charPool) {
  
    throw new Error('Не выбрано ни одного набора символов для пароля!');
  }

  const randomValues = new Uint8Array(length);
  window.crypto.getRandomValues(randomValues);


  let result = '';
  for (let i = 0; i < length; i++) {
  
    const randomIndex = randomValues[i] % charPool.length;
    result += charPool[randomIndex];
  }

  return result;
}
async function refreshPasswordList() {
  const passwordTableBody = document.getElementById('passwordTableBody');
  passwordTableBody.innerHTML = ''; 
  const passwords = await getAllPasswords();

  for (const entry of passwords) {
    const row = document.createElement('tr');

    const websiteCell = document.createElement('td');
    websiteCell.textContent = entry.website;
    row.appendChild(websiteCell);
    const usernameCell = document.createElement('td');
    usernameCell.textContent = entry.username;
    row.appendChild(usernameCell);

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
    generatedPasswordInput.value = generatedPass;
  } catch (error) {
    alert(error.message);
  }
}

async function handleAddPasswordSubmit(event) {
  event.preventDefault();

  const websiteInput = document.getElementById('website');
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');

  const website = websiteInput.value.trim();
  const username = usernameInput.value.trim();
  const plainPassword = passwordInput.value;

  if (!website || !username || !plainPassword) {
    alert('Пожалуйста, заполните все поля (сайт, имя пользователя, пароль).');
    return;
  }

  try {
  
    const encrypted = await encryptPassword(plainPassword);

   
    await saveEncryptedPasswordToDB({
      website,
      username,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext
    });

    websiteInput.value = '';
    usernameInput.value = '';
    passwordInput.value = '';

    await refreshPasswordList();
  } catch (err) {
    console.error('Ошибка при шифровании/сохранении:', err);
    alert('Не удалось сохранить пароль.');
  }
}

async function initApp() {
  try {
    let storedKey = await getMasterKeyFromDB();
    if (!storedKey) {
      storedKey = await generateMasterKey();
      await saveMasterKeyToDB(storedKey);
    }
    rawMasterKey = storedKey;
    await refreshPasswordList();
    const generateBtn = document.getElementById('generateBtn');
    generateBtn.addEventListener('click', handleGeneratePassword);
    const passwordForm = document.getElementById('passwordForm');
    passwordForm.addEventListener('submit', handleAddPasswordSubmit);

  } catch (error) {
    console.error('Ошибка инициализации приложения:', error);
    alert('Ошибка инициализации. Проверьте консоль разработчика.');
  }
}
window.addEventListener('DOMContentLoaded', initApp);
