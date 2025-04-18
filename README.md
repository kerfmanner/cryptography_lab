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

Функція `encrypt_message` розбиває повідомлення на блоки, додає паддинг та шифрує кожен блок окремо за допомогою RSA алгоритму. Паддинг додається за стандартом PKCS#5, якій працює так, ми додаємо в кінець стільки байтів скільки нам не вистачає, і кожен з цих байтів має значення, яке дорівнює кількості байтів, яких не вистачає до повного блоку. Якщо ж повідомлення розбивається на блоки націло, то в кінці додається цілий блок з байтами зі значенням розміру блока. Це зроблено, щоб потім забирати паддинг лише забираючи кількість останнійх байтів, яка задана останнім байтом.

```python
def decrypt_message(public_key, private_key, encrypted_message):
    """Decrypt the message using RSA."""
    encrypted_blocks = get_encrypted_blocks_from_bytes(encrypted_message)
    block_byte_size = get_block_size(public_key[0])
    decrypted_message = b""

    while encrypted_blocks:
        encr_block_num = int.from_bytes(encrypted_blocks.pop(0))
        decrypted_block_num = pow(encr_block_num, private_key, public_key[0])
        decrypted_block = decrypted_block_num.to_bytes(block_byte_size)
        decrypted_message += decrypted_block

    decrypted_message = get_rid_of_padding(decrypted_message)
    return decrypted_message
```

Функія `decrypt_message` спершу розбиває на блоки розміру 256, адже нам потрібно отримати значення(числа), у які ми зашифрували кожен блок повідомлення. Далі розшифровуємо кожен блок і додаємо до повідомлення. В кінці забираємо паддинг. Повертаємо повідомлення.
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