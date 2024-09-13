try:
    import asyncio
    import aiohttp
    from mnemonic import Mnemonic
    from tronpy.keys import PrivateKey
    import bip32utils
    import hashlib
    import bech32
    from eth_account import Account
    import binascii
    from tabulate import tabulate
    import os
    import base58
except:
    print('error import')

s = 0
api_eth = "SD8YJFBVPJJTQMUMBC7E4THCNJZ9MPQS6H"
api_trx = "46a0cb18-d42a-45a3-8741-4e205e4ded41"

option = 1
choise = input('Optimization Y/n: ')
if choise == 'Y':
    option = 0

def generate_tron_address(seed_phrase):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(seed_phrase, passphrase="")
    bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
    bip32_child_key = bip32_root_key.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(
        195 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    private_key_bytes = bip32_child_key.PrivateKey()
    tron_private_key = PrivateKey(private_key_bytes)
    tron_address = tron_private_key.public_key.to_base58check_address()
    return tron_address

async def fetch_tron_balance(session, address, api_key):
    url = f"https://api.tronscan.org/api/account?address={address}"
    headers = {'Authorization': f'Bearer {api_key}'}
    try:
        async with session.get(url, headers=headers) as response:
            response.raise_for_status()
            data = await response.json()
            for token in data.get('tokenBalances', []):
                if float(token['amount']) > 0:
                    return float(token['amount'])
            return 0
    except Exception as e:
        return 0

async def fetch_eth_balance(session, address, api_key):
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            data = await response.json()
            balance_wei = int(data['result'])
            return balance_wei / 1e18
    except Exception as e:
        return 0

async def fetch_btc_balance(session, address):
    url = f"https://blockstream.info/api/address/{address}"
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            data = await response.json()
            balance_satoshis = data['chain_stats']['funded_txo_sum'] - data['chain_stats']['spent_txo_sum']
            return balance_satoshis / 1e8
    except Exception as e:
        return 0

def generate_legacy_address(seed):
    bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
    bip32_child_key = bip32_root_key.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    public_key = bip32_child_key.PublicKey()
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    checksum = hashlib.sha256(hashlib.sha256(b'\x00' + ripemd160).digest()).digest()[:4]
    legacy_address = base58.b58encode(b'\x00' + ripemd160 + checksum).decode('utf-8')
    return legacy_address

def generate_p2sh_address(seed):
    bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
    bip32_child_key = bip32_root_key.ChildKey(49 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    public_key = bip32_child_key.PublicKey()
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    redeem_script = b'\x00\x14' + ripemd160
    hash160 = hashlib.new('ripemd160', hashlib.sha256(redeem_script).digest()).digest()
    checksum = hashlib.sha256(hashlib.sha256(b'\x05' + hash160).digest()).digest()[:4]
    p2sh_address = base58.b58encode(b'\x05' + hash160 + checksum).decode('utf-8')
    return p2sh_address

def generate_taproot_address(seed):
    bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
    bip32_child_key = bip32_root_key.ChildKey(86 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    public_key = bip32_child_key.PublicKey()
    sha256 = hashlib.sha256(public_key).digest()
    taproot_address = bech32.encode('bc', 1, sha256)
    return taproot_address

def generate_bech32_address(seed):
    bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
    bip32_child_key = bip32_root_key.ChildKey(84 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
    public_key = bip32_child_key.PublicKey()
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new("ripemd160", sha256).digest()
    bech32_address = bech32.encode("bc", 0, ripemd160)
    return bech32_address

async def main():
    global api_eth, api_trx, bot, option, s, id
    mnemo = Mnemonic("english")
    tron_api_key = api_trx
    etherscan_api_key = api_eth
    run = True

    async with aiohttp.ClientSession() as session:
        while run:
            phrase = mnemo.generate(strength=128)
            seed = mnemo.to_seed(phrase)

            tron_address = generate_tron_address(phrase)
            btc_address_legacy = generate_legacy_address(seed)
            btc_address_p2sh = generate_p2sh_address(seed)
            btc_address_segwit = generate_bech32_address(seed)
            btc_address_taproot = generate_taproot_address(seed)

            bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
            bip32_child_key = bip32_root_key.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(60 + bip32utils.BIP32_HARDEN).ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(0)
            private_key_bytes = bip32_child_key.PrivateKey()
            private_key = binascii.hexlify(private_key_bytes).decode()
            account = Account.from_key(private_key)
            eth_address = account.address

            # Use asyncio.gather to run balance fetches concurrently
            tasks = [
                fetch_tron_balance(session, tron_address, tron_api_key),
                fetch_eth_balance(session, eth_address, etherscan_api_key),
                fetch_btc_balance(session, btc_address_legacy),
                fetch_btc_balance(session, btc_address_p2sh),
                fetch_btc_balance(session, btc_address_segwit),
                fetch_btc_balance(session, btc_address_taproot)
            ]

            results = await asyncio.gather(*tasks)
            tron_balance, eth_balance, btc_balance_legacy, btc_balance_p2sh, btc_balance_segwit, btc_balance_taproot = results

            if option == 0:
                os.system('cls')

            table = [
                ["Seed Phrase", phrase],
                ["TRC20 Address", tron_address],
                ["TRC20 Balance (USDT)", f"{tron_balance:.6f}"],
                ["BTC Legacy Address", btc_address_legacy],
                ["BTC Legacy Balance (BTC)", f"{btc_balance_legacy:.8f}"],
                ["BTC P2SH Address", btc_address_p2sh],
                ["BTC P2SH Balance (BTC)", f"{btc_balance_p2sh:.8f}"],
                ["BTC SegWit Address", btc_address_segwit],
                ["BTC SegWit Balance (BTC)", f"{btc_balance_segwit:.8f}"],
                ["BTC Taproot Address", btc_address_taproot],
                ["BTC Taproot Balance (BTC)", f"{btc_balance_taproot:.8f}"],
                ["ETH Address", eth_address],
                ["ETH Balance (ETH)", f"{eth_balance:.6f}"]
            ]

            s += 1
            print('\n')
            print(tabulate(table, headers=["number", f'{str(s)}'], tablefmt="grid"))

            if any(balance > 0 for balance in [tron_balance, eth_balance, btc_balance_legacy, btc_balance_p2sh, btc_balance_segwit, btc_balance_taproot]):
                print("Balance found!")
                run = False
            else:
                await asyncio.sleep(0.1)

if __name__ == "__main__":
    asyncio.run(main())

