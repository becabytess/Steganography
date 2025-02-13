# Image Steganography App

This is a cool Python-based image steganography application that enables users to hide text within images with added encryption using a password. The hidden text is securely embedded into the image pixels, and decryption is performed only if the correct password is provided. This project uses Streamlit for the web interface, the Python Imaging Library (PIL) for image manipulation, and the Cryptography library for encryption and decryption.

## Features

- **Text Embedding:** Embed text into an image by modifying the least significant bits of the image pixels.
- **Encryption:** Automatically encrypt the text with a user-provided password using Fernet symmetric encryption.
- **Decryption:** Retrieve and decrypt the hidden text from the image using the correct password.
- **User-Friendly Interface:** An interactive web interface built with Streamlit, making it easy to encode and decode messages.
- **Download Option:** Download images with embedded text directly from the application.



## Live Demo

Check out the live demo of the app [here](https://hidetext.streamlit.app/).

