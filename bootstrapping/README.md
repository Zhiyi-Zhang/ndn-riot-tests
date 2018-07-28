Currently, we can't generate micro-ecc key on samr21-xpro. So we copy the bootstrap key as the communication key in our test. Also, trust anchor' key is the same as bootstrap key in test file.

Notice:
1. Anchor_key, com_key, anf ecc_key are same
2. We skip the token and BKpub hash verification.
3. We use different library of ndn-riot, please refer to https://github.com/Zhiyi-Zhang/ndn-riot for our version
