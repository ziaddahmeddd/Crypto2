using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            List<int> key = new List<int>();

            int columnCount = 0;
            int rowCount = 0;
            bool found = false;

            int i = 0;
            while (i < plainText.Length)
            {
                if (cipherText[0] == plainText[i])
                {
                    if (cipherText.Length > 1 && plainText[i + 1] == cipherText[1])
                    {
                        i++;
                    }

                    int j = i + 1;
                    while (j < plainText.Length)
                    {
                        if (cipherText[1] == plainText[j])
                        {
                            columnCount = j - i;
                            rowCount = plainText.Length / columnCount;
                            found = true;
                            break;
                        }
                        j++;
                    }
                }
                if (found)
                {
                    break;
                }
                i++;
            }

            int count = 0;
            int[,] plainMatrix = new int[rowCount, columnCount];

            int x = 0;
            while (x < rowCount)
            {
                int y = 0;
                while (y < columnCount)
                {
                    plainMatrix[x, y] = plainText[count];
                    count++;
                    y++;
                }
                x++;
            }

            int colNum = 1;
            int[] cipherKey = new int[columnCount];

            int z = 0;
            while (z < cipherText.Length - 1)
            {
                int j = 0;
                while (j < columnCount)
                {
                    if (cipherText[z] == plainMatrix[0, j] && cipherText[z + 1] == plainMatrix[1, j])
                    {
                        cipherKey[j] = colNum;
                        colNum++;
                        break;
                    }
                    j++;
                }
                z += rowCount;
            }

            key = cipherKey.ToList();

            return key;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string result = "";
            int Row = plainText.Length / key.Count;
            int index = 0;


            int remainder = plainText.Length % key.Count;
            while (remainder >= 1)
            {
                Row += 1;
                remainder = 0; // Exit the loop after adding one row
            }

            char[,] arr = new char[Row, key.Count];


            for (int i = 0; i < Row; i++)
            {
                int j = 0;
                while (j < key.Count)
                {

                    arr[i, j] = index < plainText.Length ? plainText[index++] : 'x';

                    j++;
                }
            }

            Dictionary<int, string> Map = new Dictionary<int, string>();

            for (int j = 0; j < key.Count; j++)
            {
                string str = "";

                int i = 0;
                while (i < Row)
                {
                    str += arr[i, j];
                    i++;
                }

                Map.Add(key[j], str);
            }



            int a = 1;
            while (a <= key.Count)
            {
                result += Map[a];
                a++;
            }
            return result;
        }

        public string Decrypt(string encryptedMessage, List<int> decryptionKey)
        {
            encryptedMessage = encryptedMessage.Replace(" ", "").ToLower();
            string originalMessage = "";
            int totalRows = (int)Math.Ceiling((double)(encryptedMessage.Length / (double)decryptionKey.Count()));
            char[,] decryptionMatrix = new char[totalRows, decryptionKey.Count()];
            int messageSize = encryptedMessage.Length;
            int cipherIndex = 0;
            int k = 0;

            while (k < decryptionKey.Count())
            {
                int columnIndex = decryptionKey.IndexOf(k + 1);
                int z = 0;

                while (z < totalRows)
                {
                    if (messageSize >= (z * decryptionKey.Count() + columnIndex + 1))
                    {
                        decryptionMatrix[z, columnIndex] = encryptedMessage[cipherIndex++];
                    }
                    else
                    {
                        cipherIndex--;
                    }

                    z++;
                }

                k++;
            }

            int q = 0;
            while (q < totalRows)
            {
                int j = 0;
                while (j < decryptionKey.Count())
                {
                    Console.Write(decryptionMatrix[q, j]);
                    originalMessage += decryptionMatrix[q, j];
                    j++;
                }

                q++;
            }

            return originalMessage;
        }

    }
}
