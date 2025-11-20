Project Structure:

/src
    key_generation.py
    certificate_maker.py
    certificate_verifier.py
    tamper_certificate.py

/inputs
    key_generation_input.json
    certificate_maker_input.json
    certificate_verifier_input.json
    certificate_tamper_input.json

/assets
    Northcap Logo.png
    Signature.png
    Official.jpg

/outputs
    issuer_portal_keys/
    originals/
    tampered/
    verified/

README.md


How to Run:

python -u ./key_generation.py
python -u ./certificate_maker_02.py
python -u ./certificate_verifier_02.py
python -u ./tamper_certificate_02.py
python -u ./certificate_verifier_02.py



How Tampering is Detected

Signature validity --> If the Dilithium signature fails --> invalid.
Payload hash --> If payload is changed --> invalid.
Visual text hash --> If only visible text is changed --> invalid.
Missing metadata --> If someone removes payload/signature --> invalid.
Wrong public key --> If attacker signs with their own key --> invalid.

This ensures strong post-quantum integrity protection.



Author:

Praveenraj Jothi
M.Tech Cybersecurity
The NorthCap University