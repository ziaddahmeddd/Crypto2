using System;
using System.Text;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        private string GenerateAutokey(string plainText, string key)
        {
            StringBuilder autoKey = new StringBuilder(key);
            autoKey.Append(plainText.Substring(0, plainText.Length - key.Length));
            return autoKey.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            string autoKey = GenerateAutokey(plainText, key);
            StringBuilder cipherText = new StringBuilder();

            for (int i = 0; i < plainText.Length; ++i)
            {
                char encryptedChar = (char)(((plainText[i] - 'a' + autoKey[i] - 'a') % 26) + 'A');
                cipherText.Append(encryptedChar);
            }
            return cipherText.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            StringBuilder decryptedText = new StringBuilder();
            StringBuilder currentKey = new StringBuilder(key);

            for (int i = 0; i < cipherText.Length; ++i)
            {
                char decryptedChar = (char)(((cipherText[i] - 'A' - (currentKey[i] - 'a') + 26) % 26) + 'a');
                decryptedText.Append(decryptedChar);

                
                if (currentKey.Length < cipherText.Length)
                {
                    currentKey.Append(decryptedChar);
                }
            }
            return decryptedText.ToString();
        }

        public string Analyse(string plainText, string cipherText)
        {
            StringBuilder keyBuilder = new StringBuilder();

            for (int i = 0; i < plainText.Length; ++i)
            {
                char keyChar = (char)(((cipherText[i] - 'A' - (plainText[i] - 'a') + 26) % 26) + 'a');
                keyBuilder.Append(keyChar);

                if (keyBuilder.Length >= plainText.Length)
                {
                    break;
                }
            }

            string key = keyBuilder.ToString();
            return key.Substring(0, key.Length - plainText.Length + 1);
        }
    }
}
