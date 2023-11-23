using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            foreach (char c in plainText)
            {
                if (char.IsLetter(c))
                {
                    char offset = char.IsUpper(c) ? 'A' : 'a';
                    cipherText += (char)(((c + key - offset) % 26) + offset);
                }
                else
                {
                    cipherText += c;
                }
            }
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            return Encrypt(cipherText, 26 - key);
        }

        public int Analyse(string plainText, string cipherText)
        {
            if (plainText.Length != cipherText.Length)
            {
                throw new ArgumentException("Both texts must have the same length.");
            }

            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            Dictionary<char, int> charToNumberMap = new Dictionary<char, int>();
            for (char ch = 'A'; ch <= 'Z'; ch++)
            {
                charToNumberMap[ch] = ch - 'A';
            }

            int firstPlainTextChar = charToNumberMap[plainText[0]];
            int firstCipherTextChar = charToNumberMap[cipherText[0]];

            int calculatedKey = firstCipherTextChar - firstPlainTextChar;
            if (calculatedKey < 0)
            {
                calculatedKey += 26;
            }

            return calculatedKey;
        }


    }
}
