Currently, we can't generate micro-ecc key on samr21-xpro. So we copy the bootstrap key as the communication key in our test. Also, trust anchor' key is the same as bootstrap key in test file.

Notice:
1. Anchor_key, com_key, anf ecc_key are same
2. Failure of signature verification before, or after the data sent. Somehow, when initializing the default certificate, the verification      	  works well.
3. Currently, the CKpub is the plain public key, rather the CK self signed certificate.
4. We skip the token and BKpub hash verification.
