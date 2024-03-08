<?php
namespace Authorizer\JWT;

class JWT {

    private static string $secrectKey;


    public static function generateSecureSecretKey($length = 32){
        return (bin2hex(random_bytes($length)));
    }


    public static function fillSecretKey($secret_key) {
        self::$secrectKey = $secret_key;
    }
  

    public static function createToken(JWTPayload $payload) {
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode((array)$payload));
        
        $signatureJWTRequest =  self::generateBase64SignatueToken($header, $payload, self::$secrectKey);
        
        return $header.'.'.$payload.'.'.$signatureJWTRequest;
    }


    public static function validadeToken(string $token) {
        list($header, $payload, $tokenSignatureHash) = explode('.', $token);

        $signatureJWTRequest = self::generateBase64SignatueToken($header, $payload, self::$secrectKey);
   
        if($signatureJWTRequest === $tokenSignatureHash){
            $payloadData = json_decode(base64_decode($payload));
            
            if(isset($payloadData->exp) && $payloadData->exp <= time()){
                return false;
            }

            //Demais validações do token cotidar no payload

            return true;
        }
        return false;
    }


    public static function renewToken(string $token, int $seconds = 3600) {
        list($header, $payload, $tokenSignatureHash) = explode('.', $token);
        $lastSignatureToken = self::generateBase64SignatueToken($header, $payload, self::$secrectKey);

        if($lastSignatureToken === $tokenSignatureHash){
            $payload = json_decode(base64_decode($payload));
            if(isset($payload->exp)){
                $payload->exp = time()+$seconds;
            }
            $payload = base64_encode(json_encode($payload));           
            
            $newSignatureJWTRequest = self::generateBase64SignatueToken($header, $payload, self::$secrectKey);
            return $header.'.'.$payload.'.'.$newSignatureJWTRequest;
        }

        return false;
    }


    public static function getPayload(string $token){
        $payload = explode('.', $token)[1];
        return json_decode(base64_decode($payload));
    }


    private static function generateBase64SignatueToken(string $header, string $payload, string $secrectKey, string $algo = 'sha256') {
        return hash_hmac($algo, $header.$payload, $secrectKey);
    }


}