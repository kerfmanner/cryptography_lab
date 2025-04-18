## Над проектом працювали:

- **Карпіна Олеся** - реалізація функціоналу хешування SHA-256
- **Коновалов Лука** - імплементація RSA алгоритму шифрування

## Структура проєкту

- server.py - Сервер для обробки підключень та пересилання повідомлень
- client.py - Додаток для кінцевого користувача
- utils.py - Функції для генерації ключів, шифрування та дешифрування

### Генерація RSA ключів

```python
def make_key_pair():
    """Makes two keys public and private"""
    p, q = generate_two_big_random_prime_numbers()
    n = p * q
    ctf = carmichell_totient_function(p, q)
    public_key = (n, EXPONENENT)
    private_key = find_secret_exponent(ctf, EXPONENENT)
    return public_key, private_key
```

Функція генерує пару ключів (публічний і приватний) на основі двох великих простих чисел, використовуючи методи генерації випадкових чисел та перевірки на простоту через тест Ферма.

### Шифрування та дешифрування повідомлень

```python
def encrypt_message(public_key, encoded_message):
    """
    Encrypts the encoded message using RSA.
    """
    encrypted_message = []
    block_size = get_block_size(public_key[0])
    pointer = 0
    encoded_message_with_padding = add_padding_to_message(block_size, encoded_message)

    while pointer != len(encoded_message_with_padding):
        encoded_block = pow(
            int.from_bytes(
                encoded_message_with_padding[pointer : pointer + block_size]
            ),
            EXPONENENT,
            public_key[0],
        )
        bytes_encoded_block = encoded_block.to_bytes(256)
        encrypted_message.append(bytes_encoded_block)
        pointer += block_size
    return b"".join(encrypted_message)
```

Функція `encrypt_message` розбиває повідомлення на блоки, додає паддинг та шифрує кожен блок окремо за допомогою RSA алгоритму.

### Хешування SHA-256 для перевірки цілісності

```python
def write_handler(self):
    while True:
        message = input()
        message = "User " + '"' + self.username + '"' + " : " + message
        hash_256 = sha256(message.encode())

        encrypted_message = encrypt_message(
            self.server_public_key, message.encode()
        )
        hash_with_message = hash_256.digest() + encrypted_message

        self.s.send(hash_with_message)
```

В методі `write_handler` класу `Client` перед відправкою повідомлення обчислюється його хеш SHA-256. Хеш додається до зашифрованого повідомлення, що дозволяє стороні одержувача переконатися в його цілісності.

### Перевірка цілісності повідомлень

```python
def read_handler(self):
    while True:
        message = self.s.recv(1024)
        hash_256_sent = message[:32]
        encrypted_message = message[32:]

        decrypted_message = decrypt_message(
            self.public_key, self.private_key, encrypted_message
        )
        hash_256 = sha256(decrypted_message)
        if hash_256.digest() == hash_256_sent:
            print(decrypted_message.decode())
        else:
            print("message might be tampered (hash mismatch)")
```

В методі `read_handler` класу `Client` повідомлення розділяється на хеш та зашифровані дані. Після дешифрування обчислюється хеш отриманого повідомлення і порівнюється з отриманим хешем. Якщо вони не співпадають, виводиться попередження про можливе підробку повідомлення.

### Запуск сервера

```python
if __name__ == "__main__":
    s = Server(9002)
    s.start()
```

### Підключення клієнта

```python
if __name__ == "__main__":
    cl = Client("127.0.0.1", 9002, "b1")
    cl.init_connection()
```

## Висновок

Створений додаток демонструє роботу криптографічних алгоритмів для забезпечення безпечного обміну повідомленнями. Використання RSA шифрування гарантує конфіденційність даних, а хешування SHA-256 забезпечує перевірку їх цілісності. Проект може бути розширений додатковими функціями, такими як аутентифікація користувачів та підтримка групових чатів.