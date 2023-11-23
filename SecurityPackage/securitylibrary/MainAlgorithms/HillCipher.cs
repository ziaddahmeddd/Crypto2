using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> foundKey = new List<int>();

            for (int a = 0; a < 26; a++)
            {
                for (int b = 0; b < 26; b++)
                {
                    for (int c = 0; c < 26; c++)
                    {
                        for (int d = 0; d < 26; d++)
                        {
                            if (CheckKeyValidity(a, b, c, d, plainText, cipherText))
                            {
                                foundKey.Add(a);
                                foundKey.Add(b);
                                foundKey.Add(c);
                                foundKey.Add(d);
                                return foundKey;
                            }
                        }
                    }
                }
            }

            if (foundKey.Count < 4)
            {
                throw new Exception("Valid key not found.");
            }

            return foundKey;
        }

        private bool CheckKeyValidity(int a, int b, int c, int d, List<int> plain, List<int> cipher)
        {
            int mod = 26;
            return ((a * plain[0] + b * plain[1]) % mod == cipher[0]) &&
                   ((a * plain[2] + b * plain[3]) % mod == cipher[2]) &&
                   ((c * plain[0] + d * plain[1]) % mod == cipher[1]) &&
                   ((c * plain[2] + d * plain[3]) % mod == cipher[3]);
        }

        public List<int> Decrypt(List<int> encodedText, List<int> secretKey)
        {
            List<int> decodedText = new List<int>();
            int keyMatrixSize = (int)Math.Sqrt(secretKey.Count);
            int[,] keyMatrix = new int[keyMatrixSize, keyMatrixSize];
            int[,] cipherMatrix;
            int[,] inverseKeyMatrix = new int[keyMatrixSize, keyMatrixSize];

            for (int x = 0; x < keyMatrixSize; x++)
            {
                for (int y = 0; y < keyMatrixSize; y++)
                {
                    keyMatrix[x, y] = secretKey[x * keyMatrixSize + y];
                }
            }

            int cipherMatrixCols = encodedText.Count / keyMatrixSize;
            cipherMatrix = new int[keyMatrixSize, cipherMatrixCols];
            for (int col = 0; col < cipherMatrixCols; col++)
            {
                for (int row = 0; row < keyMatrixSize; row++)
                {
                    cipherMatrix[row, col] = encodedText[col * keyMatrixSize + row];
                }
            }

            int det = CalculateDeterminant(keyMatrix, keyMatrixSize) % 26;
            if (det < 0) det += 26;
            int inverseDet = MultiplicativeInverse(det, 26);

            if (keyMatrixSize == 2)
            {
                SwapAndNegate(keyMatrix, inverseDet);
                inverseKeyMatrix = keyMatrix;
            }
            else
            {
                FindAdjugateMatrix(keyMatrix, inverseKeyMatrix, keyMatrixSize, inverseDet);
            }

            int[,] decryptedMatrix = MatrixMultiplication(inverseKeyMatrix, cipherMatrix, keyMatrixSize, cipherMatrixCols);
            for (int col = 0; col < cipherMatrixCols; col++)
            {
                for (int row = 0; row < keyMatrixSize; row++)
                {
                    decodedText.Add(decryptedMatrix[row, col]);
                }
            }

            if (decodedText.All(item => item == 0))
                throw new Exception("Decryption failed");

            return decodedText;
        }

        private void SwapAndNegate(int[,] matrix, int inverseDet)
        {
            int temp = matrix[0, 0];
            matrix[0, 0] = matrix[1, 1];
            matrix[1, 1] = temp;

            matrix[0, 1] *= -1 * inverseDet;
            matrix[1, 0] *= -1 * inverseDet;
            matrix[0, 0] *= inverseDet;
            matrix[1, 1] *= inverseDet;
        }

        private void FindAdjugateMatrix(int[,] originalMatrix, int[,] adjugateMatrix, int size, int inverseDet)
        {
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    int[,] minorMatrix = GetMinorMatrix(originalMatrix, i, j, size);
                    int determinant = CalculateDeterminant(minorMatrix, size - 1);
                    int cofactor = determinant * (int)Math.Pow(-1, i + j);
                    adjugateMatrix[j, i] = (cofactor * inverseDet) % 26;
                    if (adjugateMatrix[j, i] < 0) adjugateMatrix[j, i] += 26;
                }
            }
        }

        private int[,] GetMinorMatrix(int[,] matrix, int row, int column, int size)
        {
            int[,] minor = new int[size - 1, size - 1];
            for (int i = 0, mi = 0; i < size; i++)
            {
                if (i == row) continue;
                for (int j = 0, mj = 0; j < size; j++)
                {
                    if (j == column) continue;
                    minor[mi, mj] = matrix[i, j];
                    mj++;
                }
                mi++;
            }
            return minor;
        }

        private int[,] MatrixMultiplication(int[,] matA, int[,] matB, int rowsA, int colsB)
        {
            int commonDim = matA.GetLength(1);
            int[,] result = new int[rowsA, colsB];

            for (int i = 0; i < rowsA; i++)
            {
                for (int j = 0; j < colsB; j++)
                {
                    result[i, j] = 0;
                    for (int k = 0; k < commonDim; k++)
                    {
                        result[i, j] += matA[i, k] * matB[k, j];
                    }
                    result[i, j] %= 26;
                    if (result[i, j] < 0)
                    {
                        result[i, j] += 26;
                    }
                }
            }
            return result;
        }

        private int CalculateDeterminant(int[,] matrix, int size)
        {
            int determinant = 0;
            if (size == 1)
            {
                return matrix[0, 0];
            }
            if (size == 2)
            {
                return matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
            }

            for (int i = 0; i < size; i++)
            {
                int[,] minorMatrix = GetMinorMatrix(matrix, 0, i, size);
                determinant += (int)Math.Pow(-1, i) * matrix[0, i] * CalculateDeterminant(minorMatrix, size - 1);
            }
            return determinant;
        }

        private int MultiplicativeInverse(int a, int mod)
        {
            int m0 = mod;
            (int x, int y) = (1, 0);

            while (a > 1)
            {
                int q = a / mod;
                (a, mod) = (mod, a % mod);
                (x, y) = (y, x - q * y);
            }

            return x < 0 ? x + m0 : x;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int n = (int)Math.Sqrt(key.Count);
            List<int> cipherText = new List<int>();

            for (int i = 0; i < plainText.Count; i += n)
            {
                for (int j = 0; j < n; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < n; k++)
                    {
                        sum += key[j * n + k] * plainText[i + k];
                    }
                    cipherText.Add(sum % 26);
                }
            }

            return cipherText;
        }

        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

        private List<int> FindInverseMatrix(List<int> matrix)
        {
            int n = (int)Math.Sqrt(matrix.Count);
            int det = CalculateDeterminant(matrix, n);
            int invDet = ModInverse(det, 26);
            List<int> adjMatrix = CalculateAdjugateMatrix(matrix, n);
            List<int> inverseMatrix = new List<int>();

            for (int i = 0; i < adjMatrix.Count; i++)
            {
                inverseMatrix.Add((adjMatrix[i] * invDet) % 26);
            }

            return inverseMatrix;
        }

        private int CalculateDeterminant(List<int> matrix, int n)
        {
            if (n == 2)
            {
                return (matrix[0] * matrix[3] - matrix[1] * matrix[2]) % 26;
            }
            throw new NotImplementedException();
        }

        private int ModInverse(int a, int m)
        {
            for (int x = 1; x < m; x++)
                if (((a % m) * (x % m)) % m == 1)
                    return x;
            return 1;
        }

        private List<int> CalculateAdjugateMatrix(List<int> matrix, int n)
        {
            List<int> adjMatrix = new List<int>(new int[n * n]);
            throw new NotImplementedException();
        }
    }
}