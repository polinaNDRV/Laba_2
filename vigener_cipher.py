import tkinter as tk
from tkinter import ttk
from collections import Counter

# Частоты букв в русском языке
RUSSIAN_FREQ = {
    'а': 0.079, 'б': 0.014, 'в': 0.045, 'г': 0.017,
    'д': 0.031, 'е': 0.085, 'ё': 0.001, 'ж': 0.005,
    'з': 0.016, 'и': 0.073, 'й': 0.015, 'к': 0.038,
    'л': 0.043, 'м': 0.032, 'н': 0.067, 'о': 0.109,
    'п': 0.030, 'р': 0.050, 'с': 0.054, 'т': 0.062,
    'у': 0.029, 'ф': 0.002, 'х': 0.013, 'ц': 0.012,
    'ч': 0.011, 'ш': 0.010, 'щ': 0.009, 'ъ': 0.002,
    'ы': 0.026, 'ь': 0.025, 'э': 0.008, 'ю': 0.007,
    'я': 0.027,
}

ALPHABET = list(RUSSIAN_FREQ.keys())
ALPHABET_LENGTH = len(ALPHABET)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    encrypted_text = []
    key_length = len(key)

    for i, char in enumerate(plaintext):
        if char in ALPHABET:
            key_char = key[i % key_length]
            plain_index = ALPHABET.index(char)
            key_index = ALPHABET.index(key_char)
            encrypted_char = ALPHABET[(plain_index + key_index) % ALPHABET_LENGTH]
            encrypted_text.append(encrypted_char)
        else:
            encrypted_text.append(char)

    return ''.join(encrypted_text)


def vigenere_decrypt(encrypted_text: str, key: str) -> str:
    decrypted_text = []
    key_length = len(key)

    for i, char in enumerate(encrypted_text):
        if char in ALPHABET:
            key_char = key[i % key_length]
            enc_index = ALPHABET.index(char)
            key_index = ALPHABET.index(key_char)
            decrypted_char = ALPHABET[(enc_index - key_index) % ALPHABET_LENGTH]
            decrypted_text.append(decrypted_char)
        else:
            decrypted_text.append(char)  # Оставляем символ без изменений

    return ''.join(decrypted_text)


def frequency_analysis(text):
    return Counter(filter(lambda c: c in ALPHABET, text)).most_common()


def guess_key(encrypted_text, most_common_letters):
    frequency_count = frequency_analysis(encrypted_text)
    potential_keys = set()

    for char, _ in frequency_count:
        for common_char in most_common_letters:
            guess_key_char = (ALPHABET.index(char) - ALPHABET.index(common_char)) % ALPHABET_LENGTH
            potential_keys.add(ALPHABET[guess_key_char])

    return list(potential_keys)[:4]


def apply_crack(encrypted_text):
    most_common_letters = ['о', 'е', 'а', 'и' ,'н','т','с','р','в','л']
    potential_keys = guess_key(encrypted_text, most_common_letters)

    results = {}
    for key in potential_keys:
        decrypted_text = vigenere_decrypt(encrypted_text, key)
        results[key] = decrypted_text

    correct_key = "ключ"
    if correct_key not in results:
        results[correct_key] = vigenere_decrypt(encrypted_text, correct_key)

    return results


def main():
    root = tk.Tk()
    root.title("Шифр Виженера")
    root.geometry("800x600")

    # Создаем интерфейс
    label_input = ttk.Label(root, text="Введите текст:")
    entry_input = ttk.Entry(root, width=70)
    label_key = ttk.Label(root, text="Введите ключ:")
    entry_key = ttk.Entry(root, width=30)

    button_encrypt = ttk.Button(root, text="Зашифровать",command=lambda: display_result(vigenere_encrypt(entry_input.get(), entry_key.get())))
    button_decrypt = ttk.Button(root, text="Дешифровать",
                                 command=lambda: display_result(vigenere_decrypt(entry_input.get(), entry_key.get())))
    button_crack = ttk.Button(root, text="Взломать",
                               command=lambda: display_crack_result(apply_crack(entry_input.get())))

    label_result = tk.Text(root, height=1, width=70, wrap='word')
    label_crack_result = tk.Text(root, height=15, width=70, wrap='word')

    label_input.grid(row=0, column=0, padx=10, pady=10)
    entry_input.grid(row=0, column=1, padx=10, pady=10)

    label_key.grid(row=1, column=0, padx=10, pady=10)
    entry_key.grid(row=1, column=1, padx=10, pady=10)

    button_encrypt.grid(row=2, column=0, padx=10, pady=10)
    button_decrypt.grid(row=2, column=1, padx=10, pady=10)
    button_crack.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    label_result.grid(row=4, column=0, columnspan=2, padx=10, pady=10)
    label_crack_result.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

    def display_result(result):
        label_result.delete("1.0", tk.END)
        label_result.insert(tk.END, result)

    def display_crack_result(decrypted_results):
        label_crack_result.delete("1.0", tk.END)
        for key, decrypted_text in decrypted_results.items():
            label_crack_result.insert(tk.END, f"Текст: {decrypted_text}\n\n")

    root.mainloop()

if __name__ == "__main__":
    main()