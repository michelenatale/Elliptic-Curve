

using System.Security.Cryptography;

namespace michele.natale.EcCurveDsaDh;

partial class EcService
{
  public static ECCurve EC_STANDARD
  {
    get;
  } = ECCurve.NamedCurves.nistP256;

  public static EcCryptionAlgorithm ToEcCryptionAlgorithm(string ec_crypt_algo)
  {
    return ec_crypt_algo switch
    {
      string obj when obj == EcCryptionAlgorithm.AES.ToString() => EcCryptionAlgorithm.AES,
      string obj when obj == EcCryptionAlgorithm.AES_GCM.ToString() => EcCryptionAlgorithm.AES_GCM,
      string obj when obj == EcCryptionAlgorithm.CHACHA20_POLY1305.ToString() => EcCryptionAlgorithm.CHACHA20_POLY1305,
      _ => throw new ArgumentException($"{ec_crypt_algo} is failed"),
    };
  }

  public static byte[] DecryptionWithEcCryptionAlgo(
    ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> key,
    ReadOnlySpan<byte> associated, EcCryptionAlgorithm ec_crypt_algo)
  {
    return ec_crypt_algo switch
    {
      var obj when obj == EcCryptionAlgorithm.AES => DecryptionAes(bytes, key, associated),
      var obj when obj == EcCryptionAlgorithm.AES_GCM => DecryptionAesGcm(bytes, key, associated),
      var obj when obj == EcCryptionAlgorithm.CHACHA20_POLY1305 => DecryptionChaCha20Poly1305(bytes, key, associated),
      _ => throw new ArgumentException(),
    };
  }

  public static (string Idx, ECParameters EcParam) GenerateEcKeyPairSavePmei(
    string username, string ext = ".priv", bool encryption = true) =>
      GenerateEcKeyPairSavePmei(RngEcCurve(), username, ext, encryption);

  public static (string Idx, ECParameters EcParam) GenerateEcKeyPairSavePmei(
    ECCurve ecurve, string username,
    string ext = ".priv", bool encryption = true)
  {
    var ecparam = GenerateEcDsaKeyPair(ecurve).PrivateKey;
    var ecbytes = EcParametersInfo.SerializeEcParam(ecparam);
    var rn = NextCryptoInt64().ToString() + ext;

    var (h, f) = PMEI.EcPrivateKeyPmeiHF();
    var fp = EcSettings.ToEcCurrentFolderUser(username);
    var fn = Path.Combine(fp, rn);

    var encbytes = ecbytes;
    if (encryption)
    {
      var mpw = SHA256.HashData(EcSettings.ToMasterKey(username));
      var sd = ToUserSystemData();
      encbytes = EncryptionChaCha20Poly1305(ecbytes, mpw, sd);
    }
    var id = PMEI.SavePmeiToFile(fn, encbytes, h, f);

    return (id, ecparam);
  }


  public static (string Idx, RSAParameters RsaParam) GenerateRsaKeyPairSavePmei(
    string username, string ext = ".priv", bool encryption = true) =>
      GenerateRsaKeyPairSavePmei(username, ext, encryption, 2048);

  public static (string Idx, RSAParameters RsaParam) GenerateRsaKeyPairSavePmei(
    string username, string ext = ".priv", bool encryption = true, int keylength = 2048)
  {
    var rsaparam = GenerateRsaKeyPair(keylength).PrivateKey;
    var rsabytes = RsaParametersInfo.SerializeRsaParam(rsaparam);
    var rn = NextCryptoInt64().ToString() + ext;

    var (h, f) = PMEI.RsaPrivateKeyPmeiHF();
    var fp = EcSettings.ToEcCurrentFolderUser(username);
    var fn = Path.Combine(fp, rn);

    var encbytes = rsabytes;
    if (encryption)
    {
      var mpw = SHA256.HashData(EcSettings.ToMasterKey(username));
      var sd = ToUserSystemData();
      encbytes = EncryptionChaCha20Poly1305(rsabytes, mpw, sd);
    }
    var id = PMEI.SavePmeiToFile(fn, encbytes, h, f);

    return (id, rsaparam);
  }

  public static ECParameters EcKeyPairLoadPmei(
    string username, string index, string ext = ".priv", bool decryption = true)
  {
    var (h, f) = PMEI.EcPrivateKeyPmeiHF();
    var fp = EcSettings.ToEcCurrentFolderUser(username);
    var fn = Path.Combine(fp, index + ext);
    var (id, msg) = PMEI.LoadPmeiFromFile(fn, h, f);

    if (id.Contains(index))
    {
      var ecbytes = msg;
      if (decryption)
      {
        var mpw = SHA256.HashData(EcSettings.ToMasterKey(username));
        var sd = ToUserSystemData();
        ecbytes = DecryptionChaCha20Poly1305(msg, mpw, sd);
      }
      var ecparam = EcParametersInfo.DeserializeEcParam(ecbytes);
      return ecparam;
    }
    throw new ArgumentException($"{nameof(EcKeyPairLoadPmei)} is failed!");
  }

  public static EcMessagePackage ToEcMessagePackage(
    string cipher, string signatur, string pub_key_original,
    EcCryptionAlgorithm ec_crypt_algo)
  {
    return new EcMessagePackage
    {
      Cipher = cipher,
      Signature = signatur,
      SenderPublicKeyPmei = pub_key_original,
      EcCryptionAlgo = ec_crypt_algo.ToString(),
    };
  }

  public static RsaMessagePackage ToRsaMessagePackage(
    string cipher_msg, string cipher_shared_key,
    string signatur, string pub_key_original,
    string rsa_index, EcCryptionAlgorithm ec_crypt_algo)
  {
    return new RsaMessagePackage
    {
      Index = rsa_index,
      Signature = signatur,
      CipherMessage = cipher_msg,
      CipherSharedKey = cipher_shared_key,
      SenderPublicKey = pub_key_original,
      RsaCryptionAlgo = ec_crypt_algo.ToString(),
    };
  }

  public static EcSignedMessage ToEcSignedMessage(
    string sender_public_key_pmei,
    string signatur,
    byte[] message_hash) =>
      ToEcSignedMessage(sender_public_key_pmei, signatur,
        Convert.ToHexString(message_hash));

  public static EcSignedMessage ToEcSignedMessage(
    string sender_public_key_pmei,
    string signatur,
    string message_hash)
  {
    return new EcSignedMessage
    {
      PublicKey = sender_public_key_pmei,
      Signature = signatur,
      MessageHash = message_hash
    };
  }

  public static RsaSignedMessage ToRsaSignedMessage(
    string sender_public_key_pmei,
    string signatur,
    byte[] message_hash) =>
      ToRsaSignedMessage(sender_public_key_pmei, signatur,
        Convert.ToHexString(message_hash));
  public static RsaSignedMessage ToRsaSignedMessage(
    string sender_public_key_pmei,
    string signatur,
    string message_hash)
  {
    return new RsaSignedMessage
    {
      PublicKey = sender_public_key_pmei,
      Signature = signatur,
      MessageHash = message_hash
    };
  }

  //public static ECParameters GenerateEcExplicitKeyPair() =>
  //  GenerateEcExplicitKeyPair(EC_STANDARD);

  //public static ECParameters GenerateEcExplicitKeyPair(ECCurve ecurve)
  //{
  //  using ECDsa ecdsa = ECDsa.Create(ecurve);
  //  var result = ecdsa.ExportExplicitParameters(true);
  //  //Damit EcParams.Equals korrekt funktioniert.
  //  result.Curve = CopyOrEmpty(result.Curve);
  //  return result;
  //}

  //public static EcMessagePackage EncryptMessage(
  //  ECParameters keypair, byte[] message, EcPublicKey recipien_publicKey)
  //{
  //  using var aes = Aes.Create();
  //  aes.Key = ECDH(keypair, recipien_publicKey);
  //  var iv = aes.IV;

  //  using var ms = new MemoryStream();
  //  using var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
  //  cs.Write(message, 0, message.Length);
  //  cs.Close();

  //  string cipher = Convert.ToHexString(iv).ToLower() + "."
  //        + Convert.ToHexString(ms.ToArray()).ToLower();

  //  var signature = SignMessage(keypair, message);

  //  var result = new EcMessagePackage
  //  {
  //    Cipher = cipher,
  //    Signature = signature.Signature,
  //    SenderPublicKeyPmei = string.Empty,
  //  };

  //  return result;
  //}

  //public static bool DecryptMessage(
  //  EcMessagePackage package, ECParameters privateKey, out string message)
  //{
  //  var pubkey = new EcPublicKey(package.SenderPublicKeyPmei);
  //  var sharedkey = ECDH(privateKey, pubkey);

  //  var split = package.Cipher.Split(".");
  //  var iv = Convert.FromHexString(split[0]);
  //  var cipher = Convert.FromHexString(split[1]);

  //  using var aes = Aes.Create();
  //  aes.Key = sharedkey;
  //  aes.IV = iv;

  //  using var ms = new MemoryStream();
  //  using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);
  //  cs.Write(cipher, 0, cipher.Length);
  //  cs.Close();
  //  var decipher = ms.ToArray();

  //  var hash = SHA256.HashData(decipher);
  //  message = Encoding.UTF8.GetString(decipher);

  //  var signature = new EcSignedMessage
  //  {
  //    PublicKey = package.SenderPublicKeyPmei,
  //    Signature = package.Signature,
  //    MessageHash = Convert.ToHexString(hash)
  //  };

  //  var validation = VerifySignedMessage(signature);
  //  return validation;
  //}

  //public static EcSignedMessage SignMessage(
  //  ECParameters privatekey, byte[] message, byte prefix = 0x04)
  //{
  //  using var ecdsa = ECDsa.Create(privatekey.Curve);
  //  ecdsa.ImportParameters(new ECParameters
  //  {
  //    Curve = CopyOrEmpty(privatekey.Curve),
  //    D = [.. privatekey.D],
  //  });

  //  //with privatekey and publickey and curve
  //  var keyParameters = ecdsa.ExportExplicitParameters(true);
  //  var pubkey = ToPuplicKeyConcat(keyParameters.Q, prefix);

  //  var messagehash = SHA256.HashData(message);
  //  var signature = ecdsa.SignData(messagehash, HashAlgorithmName.SHA256);

  //  var result = new EcSignedMessage
  //  {
  //    PublicKey = Convert.ToHexString(pubkey).ToLower(),
  //    Signature = Convert.ToHexString(signature).ToLower(),
  //    MessageHash = Convert.ToHexString(messagehash).ToLower(),
  //  };

  //  return result;
  //}

  //public static bool VerifySignedMessage(EcSignedMessage message)
  //{
  //  var pubkey = EcPublicKey.FromEcPublicKeyPmei(message.PublicKey);
  //  using var ecdsa = ECDsa.Create(pubkey.PublicKey.Curve);
  //  ecdsa.ImportParameters(new ECParameters
  //  {
  //    Curve = pubkey.PublicKey.Curve,
  //    Q = pubkey.PublicKey.Q,
  //  });

  //  var hash = Convert.FromHexString(message.MessageHash);

  //  return ecdsa.VerifyData(
  //      hash,
  //      Convert.FromHexString(message.Signature),
  //      HashAlgorithmName.SHA256);
  //}

  private static byte[] ECDH(
    ECParameters privatekey, EcPublicKey publickey)
  {
    var curve = privatekey.Curve;
    using var alice = ECDiffieHellman.Create();

    alice.ImportParameters(new ECParameters
    {
      Curve = curve,
      D = [.. privatekey.D!],
    });

    curve = publickey.PublicKey.Curve;
    using var bob = ECDiffieHellman.Create();
    bob.ImportParameters(new ECParameters
    {
      Curve = curve,
      Q = publickey.ToPublicKeyEcPoint(),
    });

    //return the sharedkey
    return alice.DeriveKeyMaterial(bob.PublicKey);
  }

  public static ECCurve RngEcCurve()
  {
    var ec = ToEcCurveList();
    return ToEcCurve(ec[NextCryptoInt32(ec.Length)]);
  }

  public static ECCurve ToEcCurve(string ecname)
  {
    //var bla = ECCurve.NamedCurves.brainpoolP160r1;

    return ecname.ToLower() switch
    {
      string e when e.SequenceEqual("nistP256".ToLower()) => ECCurve.NamedCurves.nistP256,
      string e when e.SequenceEqual("nistP384".ToLower()) => ECCurve.NamedCurves.nistP384,
      string e when e.SequenceEqual("nistP521".ToLower()) => ECCurve.NamedCurves.nistP521,
      string e when e.SequenceEqual("brainpoolP160r1".ToLower()) => ECCurve.NamedCurves.brainpoolP160r1,
      string e when e.SequenceEqual("brainpoolP512t1".ToLower()) => ECCurve.NamedCurves.brainpoolP512t1,
      string e when e.SequenceEqual("brainpoolP512r1".ToLower()) => ECCurve.NamedCurves.brainpoolP512r1,
      string e when e.SequenceEqual("brainpoolP384t1".ToLower()) => ECCurve.NamedCurves.brainpoolP384t1,
      string e when e.SequenceEqual("brainpoolP384r1".ToLower()) => ECCurve.NamedCurves.brainpoolP384r1,
      string e when e.SequenceEqual("brainpoolP320t1".ToLower()) => ECCurve.NamedCurves.brainpoolP320t1,
      string e when e.SequenceEqual("brainpoolP320r1".ToLower()) => ECCurve.NamedCurves.brainpoolP320r1,
      string e when e.SequenceEqual("brainpoolP256r1".ToLower()) => ECCurve.NamedCurves.brainpoolP256r1,
      string e when e.SequenceEqual("brainpoolP224t1".ToLower()) => ECCurve.NamedCurves.brainpoolP224t1,
      string e when e.SequenceEqual("brainpoolP224r1".ToLower()) => ECCurve.NamedCurves.brainpoolP224r1,
      string e when e.SequenceEqual("brainpoolP192t1".ToLower()) => ECCurve.NamedCurves.brainpoolP192t1,
      string e when e.SequenceEqual("brainpoolP192r1".ToLower()) => ECCurve.NamedCurves.brainpoolP192r1,
      string e when e.SequenceEqual("brainpoolP160t1".ToLower()) => ECCurve.NamedCurves.brainpoolP160t1,
      string e when e.SequenceEqual("brainpoolP256t1".ToLower()) => ECCurve.NamedCurves.brainpoolP256t1,
      string e when e.SequenceEqual("secp256k1".ToLower()) => ECCurve.CreateFromFriendlyName("SecP256K1"),
      _ => throw new ArgumentException("Failed", nameof(ecname)),
    };

  }

  public static string[] ToEcCurveList()
  {
    return
    [
      "nistP256"       ,
      "nistP384"       ,
      "nistP521"       ,
      "brainpoolP160r1",
      "brainpoolP512t1",
      "brainpoolP512r1",
      "brainpoolP384t1",
      "brainpoolP384r1",
      "brainpoolP320t1",
      "brainpoolP320r1",
      "brainpoolP256r1",
      "brainpoolP224t1",
      "brainpoolP224r1",
      "brainpoolP192t1",
      "brainpoolP192r1",
      "brainpoolP160t1",
      "brainpoolP256t1",
      "secp256k1"      ,
    ];
  }
}
