from buidl.psbt import PSBT
from buidl.hd import HDPrivateKey
from io import BytesIO

MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract"

PSBT_B64 = """cHNidP8BAFICAAAAATmuiNDMoIDFGkbzmjO4o5XFcIa/suq0dPzwSXYEX7OTAQAAAAD/////AYcmAAAAAAAAFgAUIt/omUxFi3UfZe3udmqf+kfJo3oAAAAAAAEBKxAnAAAAAAAAIgAgV8V9KO3ZPhSVAz6L9BAFTjBTA6v3Jh5ue9zpMN9Vr7EBBYtRIQKsgw1c0nvywMceF18zkBpGWthmBrhvdtTaKOLekS85WCEDMubsh2ALyRkMDvmQ0/G3P7/BMztnPFpI2WR1hEj2y74hA2Odq3jSQaa+iGPkhTaIH1z7T9X4BBngghbQTdquJpDCIQOds1UQ8tnzBZxIT2itonCSaoro4gSIm+TU0VUGONpgIlSuIgYCrIMNXNJ78sDHHhdfM5AaRlrYZga4b3bU2iji3pEvOVgcOlK1zTAAAIABAACAAAAAgAIAAIAAAAAAAgAAACIGAzLm7IdgC8kZDA75kNPxtz+/wTM7ZzxaSNlkdYRI9su+HMfQZIowAACAAQAAgAAAAIACAACAAAAAAAIAAAAiBgNjnat40kGmvohj5IU2iB9c+0/V+AQZ4IIW0E3ariaQwhwSmA7tMAAAgAEAAIAAAACAAgAAgAAAAAACAAAAIgYDnbNVEPLZ8wWcSE9oraJwkmqK6OIEiJvk1NFVBjjaYCIc99BAkDAAAIABAACAAAAAgAIAAIAAAAAAAgAAAAAA"""

# BytesIO(bytes.fromhex(PSBT_HEX))

psbt_obj = PSBT.parse_base64(PSBT_B64)

hd_priv = HDPrivateKey.from_mnemonic(MNEMONIC, testnet=psbt_obj.tx_obj.testnet)

root_paths = set({})
for psbt_in in psbt_obj.psbt_ins:
    for _, details in psbt_in.named_pubs.items():
        if details.root_fingerprint.hex() == hd_priv.fingerprint().hex():
            root_paths.add(details.root_path)

private_keys = []
for root_path in root_paths:
    private_keys.append(hd_priv.traverse(root_path).private_key)

print("Signing...")
was_signed = psbt_obj.sign_with_private_keys(private_keys)
if was_signed is True:
    print(psbt_obj.serialize_base64())
else:
    print("TRANSACTION WASN'T SIGNED!")

# FIXME: display what is being signed and validate!
