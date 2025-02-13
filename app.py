import streamlit as st
from PIL import Image
import numpy as np
import os
import base64
import io
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
       algorithm=hashes.SHA256(),
       length=32,
       iterations=1000,
       salt = salt ,
       backend=default_backend())
    
    key =base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key



def bytes_to_bits(data:bytes)-> str:
    return ''.join(f'{byte:08b}' for byte in data)

def bits_to_bytes(bits: str) -> bytes:
    b = bytearray()
    for i in range(0,len(bits),8):
        byte = bits[i:i+8]
        b.append(int(byte,2))

    return bytes(b)


   

def embed_text(image: Image.Image, text: str, password: str) -> Image.Image:
    salt  = os.urandom(16)
    key = derive_key(password, salt)  
    fernet = Fernet(key=key)  
    ciphertext = fernet.encrypt(text.encode())
    data = salt + ciphertext
    header = len(data).to_bytes(4,'big')
    full_data = header + data 
    bit_string =bytes_to_bits(full_data)
    img_array = np.array(image)
    height,width,channels = img_array.shape
    total_channels = width*height*channels 
    flattened_image = img_array.flatten()

    if total_channels < len(bit_string):
        st.error("Image is too small to hold the text.")
        return None 
    for i in range(len(bit_string)):
        bit = int(bit_string[i])
        flattened_image[i] = (flattened_image[i] & 254 ) | bit 
    
    new_image = flattened_image.reshape(height,width,channels)
    return Image.fromarray(new_image.astype(np.uint8),image.mode)



        

    

def extract_text(image:Image.Image , password:str) ->str:
    
    img_array=np.array(image)
    height,width,channels = img_array.shape
    flattened_image = img_array.flatten()
    total_channels = width*height*channels 
    header_bits = ''.join(str(flattened_image[i] & 1) for i in range(4*8))
    data_length = int(header_bits,2) 
    if total_channels < data_length:
        st.error("No hidden text found in the image.")
        return None
    data_bits = ''.join(str(flattened_image[i] & 1) for i in range(32,32+data_length*8))
    data = bits_to_bytes(data_bits) 
    salt = data[:16]  
    cipher = data[16:] 
    key = derive_key(password,salt)
    fernet = Fernet(key)
    text = fernet.decrypt(cipher)
    return text.decode()


def main():
    st.title("Image Steganography App")
    app_mode = st.sidebar.selectbox("Choose the app mode", ["Encode (Hide Text)", "Decode (Extract Text)"])
    if app_mode == "Encode (Hide Text)":
        st.subheader("Hide Text in an Image and use password to encrypt it ")
        
        uploaded_file = st.file_uploader("Upload an image", type=["png", "jpg", "jpeg"])
        text_to_hide = st.text_area("Enter the text to hide")
        password = st.text_input("Enter a password", type="password")
        if st.button("Encode"):
            if uploaded_file and text_to_hide and password:
                image = Image.open(uploaded_file)
                if image.mode != 'RGB':
                    image = image.convert('RGB') 
                new_image = embed_text(image, text_to_hide, password)
                if new_image:
                    st.success("Text successfully hidden in the image!")
                    st.image(new_image, caption="Image with Hidden Text", use_column_width=True)
                    buf = io.BytesIO()
                    new_image.save(buf, format='PNG')
                    byte_im = buf.getvalue()
                    st.download_button("Download Image", byte_im, file_name="stego_image.png", mime="image/png")
            else:
                st.error("Please provide an image, text to hide, and a password.")
    elif app_mode == "Decode (Extract Text)":
        st.subheader("Extract Hidden Text from an Image")
        uploaded_file = st.file_uploader("Upload the image with hidden text", type=["png", "jpg", "jpeg"])
        password = st.text_input("Enter the password", type="password", key="decode_password")
        if st.button("Decode"):
            if uploaded_file and password:
                image = Image.open(uploaded_file)
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                hidden_text =extract_text(image,password)
                if hidden_text:
                    st.success("Hidden text successfully extracted!")
                    st.text_area("Hidden Text", hidden_text, height=200)
            else:
                st.error("Please upload an image and enter the password.")

if __name__ == "__main__":
    main()