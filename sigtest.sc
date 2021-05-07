import java.nio.charset.StandardCharsets
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.KeyFactory
import java.util.Base64
import java.security.MessageDigest

val singleSlsh = raw"\\\n *".r

//java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider)
def rfc8792single(str: String) = singleSlsh.replaceAllIn(str.stripMargin,"")
def base64Decode(str: String) = Base64.getDecoder.decode(str)

//set up keys:
val testKeyPSSPubStr: String =
   """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2\
     |+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+\
     |oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq\
     |gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W\
     |Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4\
     |aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI\
     |2wIDAQAB"""
val testKeyPSSPrivStr: String =
   """MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv\
     |P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5\
     |3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr\
     |FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA\
     |AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw\
     |9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy\
     |c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq\
     |pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X\
     |aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4\
     |XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ\
     |HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD\
     |2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N\
     |RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx\
     |DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6\
     |vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm\
     |rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi\
     |4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL\
     |FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/\
     |OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx\
     |NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR\
     |NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ\
     |3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE\
     |t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND\
     |dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF\
     |S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR\
     |rOjr9w349JooGXhOxbu8nOxX"""

//interpret keys
val testKeyPSSpub = KeyFactory.getInstance("RSA")
   .generatePublic(new X509EncodedKeySpec(base64Decode(rfc8792single(testKeyPSSPubStr))))
val testKeyPSSpriv = KeyFactory.getInstance("RSASSA-PSS")
      .generatePrivate(new PKCS8EncodedKeySpec(base64Decode(rfc8792single(testKeyPSSPrivStr))))


val sigInputStr =
   """"host": example.com
     |"date": Tue, 20 Apr 2021 02:07:55 GMT
     |"content-type": application/json
     |"@signature-params": ("host" "date" "content-type");created=1618884475;keyid="test-key-rsa-pss"""".stripMargin
val signature = "jbTIcvKyvb9Ujx0xDuDd1GD8YsJuQytESUcfWcaNWXEBh6y2RWL0Cn5jeCsVGs0CRLFhFgAkzsD2gvThWrZSW+02kNEaLVA83Auh1C3jgS0ZMZbKVU1dJICMPGhZ0VQoxr+vEOXfE3TP37vpiR6oYzJ5zgRcNAFzvnUIb5c773e/z/Rgi1p7REE/OZUHoNVGHsCz2b5mvrJ12HqIKR059UuAwRkbdkSOQJv6AZSpompbjdMuFpVHcLBzI1gwViMxGOdfpYnw7+P+AHJGmsLQLcGU+DfPle2wi6S0osMX59bT5UtLiQ++YSWQl7oujSikuRLQzAWhaEGhdBMTPlXfUA=="
println(signature)
val sigBytes = Base64.getDecoder.decode(signature)

val javaSig: java.security.Signature = {
   //	   also tried see [[https://tools.ietf.org/html/rfc7518 JSON Web Algorithms (JWA) RFC]]
   //		com.nimbusds.jose.crypto.impl.RSASSA.getSignerAndVerifier(JWSAlgorithm.PS512, new BouncyCastleProvider() )
   val rsapss = java.security.Signature.getInstance("RSASSA-PSS")
   import java.security.spec.{PSSParameterSpec, MGF1ParameterSpec}
   val pssSpec = new PSSParameterSpec(
      "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 20, 1)
   println("PSSParameterSpec=" + pssSpec)
   rsapss.setParameter(pssSpec)
   rsapss
}

val md = MessageDigest.getInstance("SHA-512")
val hash = sigInputStr.getBytes(StandardCharsets.US_ASCII)

javaSig.initVerify(testKeyPSSpub)
javaSig.update(hash)
val verify = javaSig.verify(sigBytes.toArray)

println(verify)