import os
import tempfile
import json
from typing import Optional
import ctypes
from ctypes import wintypes, c_ubyte, cast, POINTER, create_string_buffer
import secrets

PROV_RSA_FULL = 1
CALG_SHA1 = 0x00008004
CALG_3DES = 0x00006603
CRYPT_EXPORTABLE = 0x00000001
CRYPT_NEWKEYSET = 0x00000008

CRYPT_MODE_CBC = 2
KP_MODE = 4
KP_IV = 1

class SecurityManager:
    def __init__(self, data_file: str = "users.dat"):
        self.data_file = data_file
        self.temp_file: Optional[str] = None
        self.hProvider = None
        self.hKey = None
        self.salt = None
        
    def get_temp_file_path(self) -> str:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        temp_filename = "users_temp.json"
        return os.path.join(project_dir, temp_filename)
    
    def generate_salt(self, length: int = 16) -> bytes:
        return secrets.token_bytes(length)
    
    def derive_key_from_password(self, password: str, salt: bytes = None) -> bool:
        try:
            if salt is None:
                self.salt = self.generate_salt()
            else:
                self.salt = salt
            
            print(f"Используется salt: {self.salt.hex()}")
            
            self.hProvider = wintypes.HANDLE()
            if not ctypes.windll.advapi32.CryptAcquireContextW(
                ctypes.byref(self.hProvider),
                None,
                None,
                PROV_RSA_FULL,
                0
            ):
                if not ctypes.windll.advapi32.CryptAcquireContextW(
                    ctypes.byref(self.hProvider),
                    None,
                    None,
                    PROV_RSA_FULL,
                    CRYPT_NEWKEYSET
                ):
                    raise Exception("Не удалось создать криптографический контекст")
            
            hHash = wintypes.HANDLE()
            if not ctypes.windll.advapi32.CryptCreateHash(
                self.hProvider,
                CALG_SHA1,
                0,
                0,
                ctypes.byref(hHash)
            ):
                raise Exception("Не удалось создать хеш объект")
            
            password_bytes = password.encode('utf-16le')
            salted_password = self.salt + password_bytes
            
            print(f"Длина salted пароля: {len(salted_password)} байт")
            
            if not ctypes.windll.advapi32.CryptHashData(
                hHash,
                salted_password,
                len(salted_password),
                0
            ):
                ctypes.windll.advapi32.CryptDestroyHash(hHash)
                raise Exception("Не удалось хешировать пароль")
            
            self.hKey = wintypes.HANDLE()
            if not ctypes.windll.advapi32.CryptDeriveKey(
                self.hProvider,
                CALG_3DES,
                hHash,
                CRYPT_EXPORTABLE,
                ctypes.byref(self.hKey)
            ):
                ctypes.windll.advapi32.CryptDestroyHash(hHash)
                raise Exception("Не удалось сгенерировать ключ из пароля")
            
            if not ctypes.windll.advapi32.CryptSetKeyParam(
                self.hKey,
                KP_MODE,
                ctypes.byref(wintypes.DWORD(CRYPT_MODE_CBC)),
                0
            ):
                print("Предупреждение: Не удалось установить режим CBC")
            else:
                print("Режим шифрования: CBC установлен")
            
            ctypes.windll.advapi32.CryptDestroyHash(hHash)
            print("Ключ успешно сгенерирован")
            return True
            
        except Exception as e:
            print(f"Ошибка при генерации ключа: {e}")
            self.cleanup()
            return False
    
    def encrypt_data(self, data: bytes) -> Optional[bytes]:
        if not self.hKey:
            raise Exception("Ключ не инициализирован")
        
        try:
            iv = secrets.token_bytes(8)
            print(f"Сгенерирован IV: {iv.hex()}")
            
            if not ctypes.windll.advapi32.CryptSetKeyParam(
                self.hKey,
                KP_IV,
                cast(create_string_buffer(iv), POINTER(c_ubyte)),
                0
            ):
                print("Предупреждение: Не удалось установить IV")
            else:
                print("IV успешно установлен")
            
            data_bytes = bytearray(data)
            original_len = len(data_bytes)
            
            block_size = 8
            padding = block_size - (original_len % block_size)
            if padding == 0:
                padding = block_size
            
            for i in range(padding):
                data_bytes.append(padding)
            
            padded_data = bytes(data_bytes)
            padded_len = len(padded_data)
            
            buffer_size = padded_len + block_size
            buffer = create_string_buffer(padded_data, buffer_size)
            data_len = wintypes.DWORD(padded_len)
            
            print(f"Шифруем: {padded_len} байт, буфер: {buffer_size} байт")
            print(f"Алгоритм: 3DES, Режим: CBC, Размер блока: {block_size} байт")
            
            if not ctypes.windll.advapi32.CryptEncrypt(
                self.hKey,
                0,
                1,
                0,
                cast(buffer, POINTER(c_ubyte)),
                ctypes.byref(data_len),
                buffer_size
            ):
                error_code = ctypes.windll.kernel32.GetLastError()
                raise Exception(f"Не удалось зашифровать данные. Код ошибки: {error_code}")
            
            encrypted_data = buffer.raw[:data_len.value]
            print(f"Зашифровано: {data_len.value} байт")
            
            final_data = self.salt + iv + encrypted_data
            
            return final_data
            
        except Exception as e:
            print(f"Ошибка при шифровании: {e}")
            return None

    def decrypt_data(self, encrypted_data_with_salt: bytes) -> Optional[bytes]:
        if not self.hKey:
            raise Exception("Ключ не инициализирован")
        
        try:
            salt_length = 16
            iv_length = 8
            
            if len(encrypted_data_with_salt) < salt_length + iv_length:
                raise Exception("Недостаточно данных для извлечения salt и IV")
            
            salt = encrypted_data_with_salt[:salt_length]
            iv = encrypted_data_with_salt[salt_length:salt_length + iv_length]
            encrypted_data = encrypted_data_with_salt[salt_length + iv_length:]
            
            print(f"Извлечен salt: {salt.hex()}")
            print(f"Извлечен IV: {iv.hex()}")
            print(f"Данные для дешифрования: {len(encrypted_data)} байт")
            
            if not ctypes.windll.advapi32.CryptSetKeyParam(
                self.hKey,
                KP_IV,
                cast(create_string_buffer(iv), POINTER(c_ubyte)),
                0
            ):
                print("Предупреждение: Не удалось установить IV")
            else:
                print("IV успешно установлен для дешифрования")
            
            buffer = create_string_buffer(encrypted_data)
            data_len = wintypes.DWORD(len(encrypted_data))
            
            if not ctypes.windll.advapi32.CryptDecrypt(
                self.hKey,
                0,
                1,
                0,
                cast(buffer, POINTER(c_ubyte)),
                ctypes.byref(data_len)
            ):
                error_code = ctypes.windll.kernel32.GetLastError()
                raise Exception(f"Не удалось дешифровать данные. Код ошибки: {error_code}")
            
            decrypted_data = buffer.raw[:data_len.value]
            print(f"Дешифровано: {data_len.value} байт")
            
            if decrypted_data and len(decrypted_data) > 0:
                padding = decrypted_data[-1]
                if 1 <= padding <= 8 and len(decrypted_data) >= padding:
                    if all(decrypted_data[-i] == padding for i in range(1, padding + 1)):
                        result = decrypted_data[:-padding]
                        print(f"Данные после удаления padding: {len(result)} байт")
                        return result
            
            return decrypted_data
            
        except Exception as e:
            print(f"Ошибка при дешифровании: {e}")
            return None

    def encrypt_file(self) -> bool:
        try:
            if not os.path.exists(self.temp_file):
                return True
                
            with open(self.temp_file, 'rb') as f:
                plain_data = f.read()
            
            print(f"Шифруем данные размером: {len(plain_data)} байт")
            encrypted_data = self.encrypt_data(plain_data)
            if encrypted_data:
                print(f"Данные зашифрованы, размер: {len(encrypted_data)} байт")
                with open(self.data_file, 'wb') as f:
                    f.write(encrypted_data)
                print("Файл успешно зашифрован и сохранен")
                return True
            return False
            
        except Exception as e:
            print(f"Ошибка при шифровании файла: {e}")
            return False
    
    def decrypt_file(self, password: str) -> Optional[str]:
        try:
            if not os.path.exists(self.data_file):
                print("Файл не существует, создаем новый...")
                return self.create_default_encrypted_file(password)
            
            with open(self.data_file, 'rb') as f:
                encrypted_data_with_salt = f.read()
            
            if not encrypted_data_with_salt:
                raise Exception("Файл пустой")
            
            print(f"Зашифрованный файл размером: {len(encrypted_data_with_salt)} байт")
            
            salt_length = 16
            if len(encrypted_data_with_salt) < salt_length:
                raise Exception("Некорректный формат зашифрованного файла")
            
            salt = encrypted_data_with_salt[:salt_length]
            print(f"Извлечен salt: {salt.hex()}")
            
            if not self.derive_key_from_password(password, salt):
                print("Не удалось сгенерировать ключ")
                return None
            
            decrypted_data = self.decrypt_data(encrypted_data_with_salt)
            if not decrypted_data:
                print("Не удалось дешифровать данные")
                return None
            
            print(f"Данные дешифрованы, размер: {len(decrypted_data)} байт")
            
            try:
                decoded_data = decrypted_data.decode('utf-8')
                json_data = json.loads(decoded_data)
                print("JSON валиден")
            except Exception as e:
                print(f"Дешифрованные данные не являются валидным JSON: {e}")
                print(f"Первые 100 байт: {decrypted_data[:100]}")
                return None
            
            self.temp_file = self.get_temp_file_path()
            
            with open(self.temp_file, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"Расшифрованный файл создан: {self.temp_file}")
            
            if not self.validate_admin_account():
                print("Учетная запись ADMIN не найдена")
                os.unlink(self.temp_file)
                self.temp_file = None
                return None
            
            return self.temp_file
            
        except Exception as e:
            print(f"Ошибка при дешифровании файла: {e}")
            if self.temp_file and os.path.exists(self.temp_file):
                os.unlink(self.temp_file)
                self.temp_file = None
            return None
        
    def create_default_encrypted_file(self, password: str) -> Optional[str]:
        try:
            print("Создание нового зашифрованного файла...")
            
            if not self.derive_key_from_password(password):
                print("Не удалось сгенерировать ключ")
                return None
            
            default_data = [{
                "username": "ADMIN",
                "password": "",
                "is_blocked": False,
                "password_restrictions": False,
                "is_first_login": True,
                "require_password_change": False
            }]
            
            self.temp_file = self.get_temp_file_path()
            
            with open(self.temp_file, 'w', encoding='utf-8') as f:
                json.dump(default_data, f, indent=2, ensure_ascii=False)
            
            print(f"Создан временный файл с ADMIN: {self.temp_file}")
            
            if self.encrypt_file():
                print("Файл успешно зашифрован")
                return self.temp_file
            else:
                print("Ошибка при шифровании файла")
                if os.path.exists(self.temp_file):
                    os.unlink(self.temp_file)
                self.temp_file = None
                return None
                
        except Exception as e:
            print(f"Ошибка при создании файла по умолчанию: {e}")
            if self.temp_file and os.path.exists(self.temp_file):
                os.unlink(self.temp_file)
            self.temp_file = None
            return None
    
    def validate_admin_account(self) -> bool:
        try:
            if not self.temp_file or not os.path.exists(self.temp_file):
                return False
                
            with open(self.temp_file, 'r', encoding='utf-8') as f:
                users_data = json.load(f)
            
            for user in users_data:
                if user.get('username') == 'ADMIN':
                    return True
            return False
        
        except:
            return False
    
    def save_changes(self) -> bool:
        try:
            if not self.temp_file or not os.path.exists(self.temp_file):
                return False
            
            if os.path.exists(self.data_file):
                os.unlink(self.data_file)
            
            return self.encrypt_file()
            
        except Exception as e:
            print(f"Ошибка при сохранении изменений: {e}")
            return False
    
    def cleanup(self):
        if self.temp_file and os.path.exists(self.temp_file):
            try:
                os.unlink(self.temp_file)
                print(f"Временный файл удален: {self.temp_file}")
            except:
                pass
            self.temp_file = None
        
        if self.hKey:
            ctypes.windll.advapi32.CryptDestroyKey(self.hKey)
            self.hKey = None
        
        if self.hProvider:
            ctypes.windll.advapi32.CryptReleaseContext(self.hProvider, 0)
            self.hProvider = None

    def test_encryption(self):
        test_data = b'Simple test data for encryption'
        print(f"Исходные данные ({len(test_data)} байт): {test_data}")
        
        if self.derive_key_from_password("test_password"):
            print("Ключ сгенерирован успешно")
            
            encrypted = self.encrypt_data(test_data)
            if encrypted:
                print(f"Шифрование успешно!")
                print(f"Зашифрованные данные ({len(encrypted)} байт)")
                print(f"Salt: {encrypted[:16].hex()}")
                print(f"IV: {encrypted[16:24].hex()}")
                
                decrypted = self.decrypt_data(encrypted)
                if decrypted:
                    print(f"Дешифрование успешно!")
                    print(f"Дешифрованные данные ({len(decrypted)} байт): {decrypted}")
                    print(f"Совпадение: {decrypted == test_data}")
                else:
                    print("❌ Ошибка дешифрования")
            else:
                print("❌ Ошибка шифрования")


def get_password_from_user() -> str:
    import getpass
    while True:
        password = getpass.getpass("Введите парольную фразу для доступа к системе: ")
        if password:
            return password
        else:
            print("Парольная фраза не может быть пустой!")


def initialize_security() -> Optional[SecurityManager]:
    security_mgr = SecurityManager()
    
    password = get_password_from_user()
    
    print("Попытка дешифрования файла...")
    
    temp_file = security_mgr.decrypt_file(password)
    
    if not temp_file:
        print("Ошибка: Неверная парольная фраза или поврежденный файл данных!")
        security_mgr.cleanup()
        return None
    
    print("Файл учетных данных успешно расшифрован!")
    return security_mgr