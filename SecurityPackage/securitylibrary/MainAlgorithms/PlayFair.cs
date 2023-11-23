using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        private char[,] BuildKeyMatrix(string keyPhrase)
        {
            char[] alphabet = "abcdefghiklmnopqrstuvwxyz".ToCharArray();
            char[,] keyTable = new char[5, 5];
            HashSet<char> addedChars = new HashSet<char>();
            int index = 0, alphaIndex = 0;

            keyPhrase = keyPhrase.ToLower().Replace('j', 'i');

            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    if (index < keyPhrase.Length)
                    {
                        if (!addedChars.Contains(keyPhrase[index]))
                        {
                            keyTable[row, col] = keyPhrase[index];
                            addedChars.Add(keyPhrase[index]);
                        }
                        else
                        {
                            col--;
                        }
                    }
                    else
                    {
                        while (addedChars.Contains(alphabet[alphaIndex])) alphaIndex++;
                        keyTable[row, col] = alphabet[alphaIndex];
                        addedChars.Add(alphabet[alphaIndex]);
                    }
                    index++;
                }
            }
            return keyTable;
        }

        private string SanitizePlainText(string text)
        {
            StringBuilder sanitizedText = new StringBuilder(text.ToLower().Replace('j', 'i'));
            for (int i = 0; i < sanitizedText.Length - 1; i += 2)
            {
                if (sanitizedText[i] == sanitizedText[i + 1])
                {
                    sanitizedText.Insert(i + 1, sanitizedText[i] != 'x' ? 'x' : 'y');
                    i++; 
                }
            }
            if (sanitizedText.Length % 2 != 0)
            {
                sanitizedText.Append(sanitizedText[sanitizedText.Length - 1] != 'x' ? 'x' : 'y');
            }
            return sanitizedText.ToString();
        }


        public string Decrypt(string cipherText, string key)
        {
            char[,] keyMatrix = BuildKeyMatrix(key);
            StringBuilder decryptedText = new StringBuilder();
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char firstChar = char.ToLower(cipherText[i]);
                char secondChar = char.ToLower(cipherText[i + 1]);
                int x1 = 0, y1 = 0, x2 = 0, y2 = 0;

                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (keyMatrix[row, col] == firstChar) { x1 = row; y1 = col; }
                        if (keyMatrix[row, col] == secondChar) { x2 = row; y2 = col; }
                    }
                }

                if (x1 == x2)
                {
                    decryptedText.Append(keyMatrix[x1, (y1 - 1 + 5) % 5]);
                    decryptedText.Append(keyMatrix[x2, (y2 - 1 + 5) % 5]);
                }
                else if (y1 == y2)
                {
                    decryptedText.Append(keyMatrix[(x1 - 1 + 5) % 5, y1]);
                    decryptedText.Append(keyMatrix[(x2 - 1 + 5) % 5, y2]);
                }
                else
                {
                    decryptedText.Append(keyMatrix[x1, y2]);
                    decryptedText.Append(keyMatrix[x2, y1]);
                }
            }
            return decryptedText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] keyMatrix = BuildKeyMatrix(key);
            StringBuilder encryptedText = new StringBuilder();
            string sanitizedText = SanitizePlainText(plainText);

            for (int i = 0; i < sanitizedText.Length; i += 2)
            {
                char firstChar = sanitizedText[i];
                char secondChar = sanitizedText[i + 1];
                int x1 = 0, y1 = 0, x2 = 0, y2 = 0;

                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (keyMatrix[row, col] == firstChar) { x1 = row; y1 = col; }
                        if (keyMatrix[row, col] == secondChar) { x2 = row; y2 = col; }
                    }
                }

                if (x1 == x2)
                {
                    encryptedText.Append(char.ToUpper(keyMatrix[x1, (y1 + 1) % 5]));
                    encryptedText.Append(char.ToUpper(keyMatrix[x2, (y2 + 1) % 5]));
                }
                else if (y1 == y2)
                {
                    encryptedText.Append(char.ToUpper(keyMatrix[(x1 + 1) % 5, y1]));
                    encryptedText.Append(char.ToUpper(keyMatrix[(x2 + 1) % 5, y2]));
                }
                else
                {
                    encryptedText.Append(char.ToUpper(keyMatrix[x1, y2]));
                    encryptedText.Append(char.ToUpper(keyMatrix[x2, y1]));
                }
            }
            return encryptedText.ToString();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
    }
}
