using System;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        private string GenerateFullKey(string text, string initialKey)
        {
            int textLength = text.Length;
            int keyLength = initialKey.Length;
            char[] fullKey = new char[textLength];

            for (int i = 0; i < textLength; i++)
            {
                fullKey[i] = initialKey[i % keyLength];
            }

            return new string(fullKey);
        }

        private string ExtractKey(string repeatedKey)
        {
            string coreKey = "";
            coreKey += repeatedKey[0];
            for (int i = 1; i < repeatedKey.Length; i++)
            {
                string segment = repeatedKey.Substring(0, i);
                if (repeatedKey.StartsWith(segment) && repeatedKey.EndsWith(segment))
                {
                    return segment;
                }
                coreKey += repeatedKey[i];
            }
            return coreKey;
        }

        public string Encrypt(string plainText, string key)
        {
            string completeKey = GenerateFullKey(plainText, key);
            char[] cipher = new char[plainText.Length];

            for (int i = 0; i < plainText.Length; i++)
            {
                cipher[i] = (char)(((plainText[i] - 'a' + completeKey[i] - 'a') % 26) + 'A');
            }

            return new string(cipher);
        }

        public string Decrypt(string cipherText, string key)
        {
            string completeKey = GenerateFullKey(cipherText, key);
            char[] plain = new char[cipherText.Length];

            for (int i = 0; i < cipherText.Length; i++)
            {
                plain[i] = (char)(((cipherText[i] - 'A' - (completeKey[i] - 'a') + 26) % 26) + 'a');
            }

            return new string(plain);
        }

        public string Analyse(string plainText, string cipherText)
        {
            char[] assumedKey = new char[plainText.Length];

            for (int i = 0; i < plainText.Length; i++)
            {
                assumedKey[i] = (char)(((cipherText[i] - 'A' - (plainText[i] - 'a') + 26) % 26) + 'a');
            }

            return ExtractKey(new string(assumedKey));
        }
    }
}
