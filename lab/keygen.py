from guardski.signing import generate_keypair

private, public = generate_keypair()
print("private:", private)
print("public:", public)
