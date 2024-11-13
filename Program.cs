using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace MACANSIX919;

public static class Program
{
    public static void Main()
    {
        Console.WriteLine("MAC : " + X919Mac.Execute(
            "<DATOSENTRADA><DS_MERCHANT_AMOUNT>12000</DS_MERCHANT_AMOUNT><DS_MERCHANT_ORDER>5604QQRN</DS_MERCHANT_ORDER><DS_MERCHANT_MERCHANTCODE>LUC006457891001</DS_MERCHANT_MERCHANTCODE><DS_MERCHANT_TERMINAL>01</DS_MERCHANT_TERMINAL><DS_MERCHANT_CURRENCY>986</DS_MERCHANT_CURRENCY><DS_MERCHANT_PAN>53DB70D0CF9A6A1CFAD1298E975ADC1E</DS_MERCHANT_PAN><DS_MERCHANT_EXPIRYDATE>3412</DS_MERCHANT_EXPIRYDATE><DS_MERCHANT_CVV2>123</DS_MERCHANT_CVV2><DS_MERCHANT_TRANSACTIONTYPE>A</DS_MERCHANT_TRANSACTIONTYPE><DS_MERCHANT_ACCOUNTTYPE>01</DS_MERCHANT_ACCOUNTTYPE><DS_MERCHANT_PLANTYPE>01</DS_MERCHANT_PLANTYPE><DS_MERCHANT_PLANINSTALLMENTSNUMBER>01</DS_MERCHANT_PLANINSTALLMENTSNUMBER><DS_MERCHANT_PRODUCTDESCRIPTION>ENTREPAY</DS_MERCHANT_PRODUCTDESCRIPTION><DS_MERCHANT_TITULAR>CARDHOLDER TESTE</DS_MERCHANT_TITULAR><DS_MERCHANT_MERCHANTDATA>ENTREPAY TESTE</DS_MERCHANT_MERCHANTDATA><DS_MERCHANT_CLIENTIP>127.0.0.1</DS_MERCHANT_CLIENTIP></DATOSENTRADA>"
        ));
    }
}

//8EE85D25DD682854
internal static class X919Mac
{
    private const string Key = "269289DA6EAD0B20928C8F2F2F6BC752";

    private static byte[] SubArray(byte[] data, int index, int length)
    {
        var result = new byte[length];
        Array.Copy(data, index, result, 0, length);
        return result;
    }

    private static byte[] ConvertHexStringToByteArray(string hexString)
    {
        if (hexString.Length % 2 != 0)
        {
            throw new ArgumentException($"The binary key cannot have an odd number of digits: {hexString}");
        }

        var data = new byte[hexString.Length / 2];
        for (var i = 0; i < data.Length; i++)
        {
            data[i] = byte.Parse(hexString.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return data;
    }

    private static string ConvertByteArrayToHexString(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (var b in data)
        {
            sb.Append(b.ToString("X2"));
        }

        return sb.ToString();
    }

    public static string Execute(string text)
    {
        var iv = new byte[8];
        var key = ConvertHexStringToByteArray(Key);
        var leftKey = SubArray(key, 0, 8);
        var rightKey = SubArray(key, 8, 8);
        var data = Encoding.ASCII.GetBytes(text);

        using var desAlg = DES.Create();
        desAlg.Mode = CipherMode.CBC;
        desAlg.Padding = PaddingMode.None;

        using var encryptor = desAlg.CreateEncryptor(leftKey, iv);
        using var decryptor = desAlg.CreateDecryptor(rightKey, iv);

        var result = ProcessDataBlocks(data, encryptor);

        result = EncryptBlock(decryptor, result);
        result = EncryptBlock(encryptor, result);

        return ConvertByteArrayToHexString(result);
    }

    private static byte[] ProcessDataBlocks(byte[] data, ICryptoTransform encryptor)
    {
        var dataBlock = new byte[8];
        var remain = data.Length % 8;
        var loopCount = data.Length / 8;

        if (remain == 0)
        {
            loopCount--;
            remain = 8;
        }

        Array.Copy(data, 0, dataBlock, 0, 8);
        var result = EncryptBlock(encryptor, dataBlock);

        for (var i = 1; i < loopCount; i++)
        {
            Array.Copy(data, i * 8, dataBlock, 0, 8);
            dataBlock = XorArray(dataBlock, result);
            result = EncryptBlock(encryptor, dataBlock);
        }

        var lastBlock = new byte[8];
        Array.Copy(data, data.Length - remain, lastBlock, 0, remain);
        lastBlock = XorArray(lastBlock, result);

        return EncryptBlock(encryptor, lastBlock);
    }

    private static byte[] XorArray(byte[] buffer1, byte[] buffer2)
    {
        for (var i = 0; i < buffer1.Length; i++)
        {
            buffer1[i] ^= buffer2[i];
        }

        return buffer1;
    }

    private static byte[] EncryptBlock(ICryptoTransform crypt, byte[] toEncrypt)
    {
        using var mStream = new MemoryStream();
        using var cStream = new CryptoStream(mStream, crypt, CryptoStreamMode.Write);
        cStream.Write(toEncrypt, 0, toEncrypt.Length);
        cStream.FlushFinalBlock();
        return mStream.ToArray();
    }
}