import streamlit as st
import numpy as np
from PIL import Image
from io import BytesIO
import hashlib
import secrets
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

st.set_page_config(
    page_title="Secret Image Messenger",
    page_icon="🔐",
    layout="centered"
)

MAGIC = b"STG1"


def password_key(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        300000,
        dklen=32
    )


def hide_message(image_file, message, password):
    image = Image.open(image_file).convert("RGB")
    pixels = np.array(image, dtype=np.uint8)

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = password_key(password, salt)

    encrypted = AESGCM(key).encrypt(
        nonce, message.encode("utf-8"), None
    )

    # Format: marker + encrypted packet length + salt + nonce + ciphertext
    packet = MAGIC + struct.pack(">I", len(salt + nonce + encrypted))
    packet += salt + nonce + encrypted

    bits = np.unpackbits(
        np.frombuffer(packet, dtype=np.uint8)
    )

    flat = pixels.reshape(-1)
    if len(bits) > len(flat):
        raise ValueError(
            "Image is too small. Please choose a larger PNG image."
        )

    flat[:len(bits)] = (
        (flat[:len(bits)] & 254) | bits
    )

    output = BytesIO()
    Image.fromarray(pixels).save(output, format="PNG")
    output.seek(0)
    return output


def extract_message(image_file, password):
    image = Image.open(image_file).convert("RGB")
    pixels = np.array(image, dtype=np.uint8).reshape(-1)

    def read_bytes(start, count):
        if start + count * 8 > len(pixels):
            raise ValueError("Image does not contain a complete message.")
        bits = pixels[start:start + count * 8] & 1
        return np.packbits(bits).tobytes()

    header = read_bytes(0, 8)
    if header[:4] != MAGIC:
        raise ValueError("No hidden message found in this image.")

    packet_length = struct.unpack(">I", header[4:8])[0]
    if packet_length < 29 or packet_length > (len(pixels) // 8 - 8):
        raise ValueError("Invalid hidden data or damaged image.")

    packet = read_bytes(64, packet_length)
    salt = packet[:16]
    nonce = packet[16:28]
    encrypted = packet[28:]

    key = password_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, encrypted, None)
    return plaintext.decode("utf-8")


st.title("🔐 Image Steganography")
st.subheader("Secret Message Protection")
st.write("Hide an encrypted secret message inside a PNG image.")

hide_tab, extract_tab = st.tabs(
    ["Hide Message", "Extract Message"]
)

with hide_tab:
    st.header("Hide Your Secret Message")

    image = st.file_uploader(
        "Upload your image",
        type=["png", "jpg", "jpeg"],
        key="hide_image"
    )

    message = st.text_area("Enter your secret message")
    password = st.text_input(
        "Create a password",
        type="password",
        key="hide_password"
    )

    if image:
        st.image(image, caption="Selected image")

    if st.button("Hide Message"):
        if not image or not message or not password:
            st.warning("Upload an image and enter both message and password.")
        else:
            try:
                result = hide_message(image, message, password)
                st.success("Your encrypted message is hidden in the image!")
                st.download_button(
                    "Download Secret PNG",
                    data=result.getvalue(),
                    file_name="secret_image.png",
                    mime="image/png"
                )
            except Exception as error:
                st.error(str(error))


with extract_tab:
    st.header("Extract Your Secret Message")

    received_image = st.file_uploader(
        "Upload the secret PNG image",
        type=["png"],
        key="received_image"
    )

    extract_password = st.text_input(
        "Enter the password",
        type="password",
        key="extract_password"
    )

    if st.button("Extract Message"):
        if not received_image or not extract_password:
            st.warning("Upload the secret PNG and enter the password.")
        else:
            try:
                secret = extract_message(
                    received_image, extract_password
                )
                st.success("Message decrypted successfully!")
                st.text_area(
                    "Your Secret Message",
                    value=secret,
                    height=150
                )
            except Exception:
                st.error(
                    "Could not extract the message. "
                    "Check the image and password."
                )