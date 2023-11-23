using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Encrypt(string plainText, string key)
        {
            Dictionary<char, char> map = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                map.Add((char)('A' + i), key[i]);
            }

            string cipherText = "";
            foreach (char c in plainText.ToUpper())
            {
                if (char.IsLetter(c))
                {
                    cipherText += map[c];
                }
                else
                {
                    cipherText += c;
                }
            }
            return cipherText;
        }

        public string Decrypt(string cipherText, string key)
        {
            Dictionary<char, char> charMapping = new Dictionary<char, char>();
            StringBuilder decryptedText = new StringBuilder();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();

            for (int idx = 0; idx < 26; idx++)
            {
                charMapping.Add((char)('A' + idx), key[idx]);
            }

            foreach (char cipherChar in cipherText)
            {
                char plainChar = charMapping.FirstOrDefault(x => x.Value == cipherChar).Key;
                decryptedText.Append(plainChar);
            }

            return decryptedText.ToString().ToLower();
        }

        public string Analyse(string plainText, string cipherText)
        {
            Dictionary<int, char> keyDict = new Dictionary<int, char>();
            List<char> remainingChars = Enumerable.Range('a', 'z' - 'a' + 1).Select(x => (char)x).ToList();
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
            {
                int alphabetIndex = plainText[i] - 'a';
                char cipherChar = cipherText[i];
                if (!keyDict.ContainsKey(alphabetIndex))
                {
                    keyDict[alphabetIndex] = cipherChar;
                }
                remainingChars.Remove(cipherChar);
            }

            for (int i = 0; i < 26; i++)
            {
                if (!keyDict.ContainsKey(i))
                {
                    keyDict[i] = remainingChars[0];
                    remainingChars.RemoveAt(0);
                }
            }

            char[] finalKey = new char[26];
            foreach (var pair in keyDict)
            {
                finalKey[pair.Key] = pair.Value;
            }

            return new string(finalKey);
        }

        public string AnalyseUsingCharFrequency(string cipher)
        {
            string freqOrder = "ETAOINSRHLDUCMFYWGPBVKXQJZ";
            Dictionary<char, int> freqCount = new Dictionary<char, int>();

            for (char c = 'A'; c <= 'Z'; c++)
            {
                freqCount[c] = 0;
            }

            foreach (char c in cipher)
            {
                if (char.IsLetter(c))
                {
                    freqCount[char.ToUpper(c)]++;
                }
            }

            var sortedFreq = freqCount.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);

            Dictionary<char, char> keyMap = new Dictionary<char, char>();
            int i = 0;
            foreach (var item in sortedFreq)
            {
                keyMap[item.Key] = freqOrder[i];
                i++;
            }

            string decryptedText = "";
            foreach (char c in cipher)
            {
                if (char.IsLetter(c))
                {
                    decryptedText += keyMap[char.ToUpper(c)];
                }
                else
                {
                    decryptedText += c;
                }
            }

            return decryptedText;
        }
    }
}
