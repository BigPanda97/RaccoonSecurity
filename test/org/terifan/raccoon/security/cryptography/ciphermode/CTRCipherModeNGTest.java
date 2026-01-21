package org.terifan.raccoon.security.cryptography.ciphermode;

import java.security.SecureRandom;
import java.util.Arrays;
import org.terifan.raccoon.security.cryptography.AES;
import org.terifan.raccoon.security.cryptography.Kuznechik;
import org.terifan.raccoon.security.cryptography.SecretKey;
import org.terifan.raccoon.security.cryptography.Serpent;
import org.terifan.raccoon.security.cryptography.Twofish;
import org.testng.annotations.Test;


public class CTRCipherModeNGTest extends CipherModeHelper
{
	@Test
	public void testEncryption()
	{
		testBlockEncryption(new CTRCipherMode(), new AES(), new AES(), 16);
		testBlockEncryption(new CTRCipherMode(), new AES(), new AES(), 24);
		testBlockEncryption(new CTRCipherMode(), new AES(), new AES(), 32);
		testBlockEncryption(new CTRCipherMode(), new Kuznechik(), new Kuznechik(), 32);
		testBlockEncryption(new CTRCipherMode(), new Twofish(), new Twofish(), 8);
		testBlockEncryption(new CTRCipherMode(), new Twofish(), new Twofish(), 16);
		testBlockEncryption(new CTRCipherMode(), new Twofish(), new Twofish(), 24);
		testBlockEncryption(new CTRCipherMode(), new Twofish(), new Twofish(), 32);
		testBlockEncryption(new CTRCipherMode(), new Serpent(), new Serpent(), 16);
		testBlockEncryption(new CTRCipherMode(), new Serpent(), new Serpent(), 24);
		testBlockEncryption(new CTRCipherMode(), new Serpent(), new Serpent(), 32);
	}


	@Test(enabled = false)
	public void testOddLength()
	{
		AES cipher = new AES(new SecretKey(new byte[16]));
		AES tweakCipher = new AES(new SecretKey(new byte[16]));
		SecureRandom prng = new SecureRandom();
		int[] iv =
		{
			1, 2, 3, 4
		};

		for (int u = 1; u <= 8; u++)
		{
			for (int z = 1; z < 100; z++)
			{
				byte[] data = new byte[z];

				new CTRCipherMode().encrypt(data, 0, data.length, cipher, 0, 16 * u, iv, tweakCipher);

//				Debug.hexDump(1024, data);
//				if(data[data.length-1]==0)throw new IllegalStateException();
				new CTRCipherMode().decrypt(data, 0, data.length, cipher, 0, 16 * u, iv, tweakCipher);

//				Debug.hexDump(1024, data);
				if (!Arrays.equals(data, new byte[data.length]))
				{
					throw new IllegalStateException();
				}
			}
		}
	}
}
