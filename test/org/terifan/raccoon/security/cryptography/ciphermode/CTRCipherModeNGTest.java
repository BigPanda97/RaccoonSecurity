package org.terifan.raccoon.security.cryptography.ciphermode;

import java.util.HexFormat;
import java.util.Random;
import org.terifan.raccoon.security.cryptography.AES;
import org.terifan.raccoon.security.cryptography.Kuznechik;
import org.terifan.raccoon.security.cryptography.SecretKey;
import org.terifan.raccoon.security.cryptography.Serpent;
import org.terifan.raccoon.security.cryptography.Twofish;
import static org.testng.Assert.assertEquals;
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


	@Test
	public void testOddLength()
	{
		AES cipher = new AES(new SecretKey(new byte[16]));
		AES tweak = new AES(new SecretKey(new byte[16]));
		int[] iv = new int[4];
		Random prng = new Random();

		for (int unitSize = 1; unitSize <= 8; unitSize++)
		{
			for (int length = 1; length < 100; length++)
			{
				byte[] buffer = new byte[length];
				prng.nextBytes(buffer);
				byte[] input = buffer.clone();

				new CTRCipherMode().encrypt(buffer, 0, length, cipher, 0, 16 * unitSize, iv, tweak);

				System.out.printf("%d %2d %s%n", unitSize, length, HexFormat.of().formatHex(buffer));

				new CTRCipherMode().decrypt(buffer, 0, length, cipher, 0, 16 * unitSize, iv, tweak);

				assertEquals(buffer, input);
			}
		}
	}
}
