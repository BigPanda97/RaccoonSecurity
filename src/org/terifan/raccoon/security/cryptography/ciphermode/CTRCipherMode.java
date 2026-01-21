package org.terifan.raccoon.security.cryptography.ciphermode;

import org.terifan.raccoon.security.cryptography.BlockCipher;


/**
 * AES-CTR (Counter) mode – compatible with NIST SP-800-38A. No padding is applied; callers may pass arbitrary-length data.
 */
public final class CTRCipherMode extends CipherMode
{
	private static final int BLOCK_SIZE = 16;              // 128-bit blocks


	/**
	 * @param aBuffer the buffer to encrypt
	 * @param aOffset offset in the buffer where to start encryption
	 * @param aLength number of bytes to process, length may be partial block sizes
	 * @param aCipher the cipher to use
	 * @param aStartDataUnitNo index of the data unit, usually the offset dived by unit size
	 * @param aUnitSize must be a multiple of block size (16)
	 * @param aBlockIV  the initialization vector
	 * @param aTweakCipher the tweak cipher to use to update the IV
	 */
	@Override
	public void encrypt(final byte[] aBuffer, int aOffset, final int aLength, final BlockCipher aCipher, long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher)
	{
		update(aBuffer, aOffset, aLength, aCipher, aStartDataUnitNo, aUnitSize, aBlockIV, aTweakCipher);
	}


	/**
	 * @param aBuffer the buffer to decrypt
	 * @param aOffset offset in the buffer where to start decryption
	 * @param aLength number of bytes to process, length may be partial block sizes
	 * @param aCipher the cipher to use
	 * @param aStartDataUnitNo index of the data unit, usually the offset dived by unit size
	 * @param aUnitSize must be a multiple of block size (16)
	 * @param aBlockIV  the initialization vector
	 * @param aTweakCipher the tweak cipher to use to update the IV
	 */
	@Override
	public void decrypt(final byte[] aBuffer, int aOffset, final int aLength, final BlockCipher aCipher, long aStartDataUnitNo, final int aUnitSize, final int[] aBlockIV, BlockCipher aTweakCipher)
	{
		update(aBuffer, aOffset, aLength, aCipher, aStartDataUnitNo, aUnitSize, aBlockIV, aTweakCipher);
	}


	private static void update(byte[] aBuffer, int aOffset, int aLength, BlockCipher aCipher, long aStartDataUnitNo, int aUnitSize, int[] aBlockIV, BlockCipher aTweakCipher)
	{
		assert aUnitSize % BLOCK_SIZE == 0;

		byte[] counter = new byte[BLOCK_SIZE];		// clear-text counter
		byte[] ks = new byte[BLOCK_SIZE];			// encrypted keystream

		int units = aLength / aUnitSize;
		int blockCount = aUnitSize / BLOCK_SIZE;

		for (int u = 0; u < units; u++)
		{
			// IV ⊕ data-unit #  →  counter[0..15] (SP-800-38A §D.1)
			prepareIV(aBlockIV, aStartDataUnitNo++, counter, aTweakCipher);

			for (int blockIndex = 0; blockIndex < blockCount; blockIndex++, aOffset += BLOCK_SIZE)
			{
				aCipher.engineEncryptBlock(counter, 0, ks, 0);	// E_k(counter)

				xor(aBuffer, aOffset, BLOCK_SIZE, ks, 0);						// C/P ⊕ KS

				increment(counter);								// clear counter++ (big-endian)
			}
		}

		// process short than aUnitSize tail unit

		int remainingBytes = aLength % aUnitSize;
		if (remainingBytes > 0)
		{
			blockCount = remainingBytes / BLOCK_SIZE;

			// IV ⊕ data-unit #  →  counter[0..15] (SP-800-38A §D.1)
			prepareIV(aBlockIV, aStartDataUnitNo++, counter, aTweakCipher);

			for (int blockIndex = 0; blockIndex < blockCount; blockIndex++, aOffset += BLOCK_SIZE)
			{
				aCipher.engineEncryptBlock(counter, 0, ks, 0);	// E_k(counter)

				xor(aBuffer, aOffset, BLOCK_SIZE, ks, 0);						// C/P ⊕ KS

				increment(counter);								// clear counter++ (big-endian)
			}

			// process shorter than BLOCK_SIZE tail block

			remainingBytes %= BLOCK_SIZE;
			if (remainingBytes > 0)
			{
				aCipher.engineEncryptBlock(counter, 0, ks, 0);	// E_k(counter)

				for (int i = 0; i < remainingBytes; i++, aOffset++)
				{
					aBuffer[aOffset] ^= ks[i];
				}
			}
		}
	}


	/**
	 * Increment 128-bit big-endian counter in-place.
	 */
	private static void increment(byte[] ctr)
	{
		for (int i = BLOCK_SIZE; --i >= 0 && ++ctr[i] == 0;)
		{
		}
	}
}
