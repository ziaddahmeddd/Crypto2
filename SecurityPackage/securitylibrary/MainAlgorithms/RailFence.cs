using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            if (key <= 1 || key >= plainText.Length)
                return plainText;

            var layers = new StringBuilder[key];
            for (int i = 0; i < key; i++)
                layers[i] = new StringBuilder();

            int currentLayer = 0;
            int direction = 1;

            foreach (char c in plainText)
            {
                layers[currentLayer].Append(c);

                if (currentLayer == 0)
                    direction = 1;
                else if (currentLayer == key - 1)
                    direction = -1;

                currentLayer += direction;
            }

            return string.Join("", layers.Select(l => l.ToString()));
        }

        public string Decrypt(string cipherText, int key)
        {
            if (key <= 1 || key >= cipherText.Length)
                return cipherText;

            var layers = new StringBuilder[key];
            int[] layerLengths = new int[key];

            int currentLayer = 0;
            int direction = 1;

            foreach (char c in cipherText)
            {
                if (currentLayer == 0)
                    direction = 1;
                else if (currentLayer == key - 1)
                    direction = -1;

                layerLengths[currentLayer]++;
                currentLayer += direction;
            }

            int currentChar = 0;
            for (int layer = 0; layer < key; layer++)
            {
                layers[layer] = new StringBuilder(cipherText.Substring(currentChar, layerLengths[layer]));
                currentChar += layerLengths[layer];
            }

            StringBuilder result = new StringBuilder();
            currentLayer = 0;
            direction = 1;

            while (result.Length < cipherText.Length)
            {
                result.Append(layers[currentLayer][0]);
                layers[currentLayer].Remove(0, 1);

                if (currentLayer == 0)
                    direction = 1;
                else if (currentLayer == key - 1)
                    direction = -1;

                currentLayer += direction;
            }

            return result.ToString();
        }

        public int Analyse(string plainText, string cipherText)
        {
            for (int key = 2; key <= plainText.Length; key++)
            {
                if (Encrypt(plainText, key).Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                {
                    return key;
                }
            }

            return -1; // Key not found
        }
    }
}
