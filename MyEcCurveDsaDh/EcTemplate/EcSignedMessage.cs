﻿

namespace michele.natale.EcCurveDsaDh;

public class EcSignedMessage
{
  //All relevant data required for verification.
  public required string PublicKey
  {
    get; set;
  }
  public required string Signature
  {
    get; set;
  }
  public required string MessageHash
  {
    get; set;
  }
}