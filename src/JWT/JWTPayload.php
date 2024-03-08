<?php

namespace Authorizer\JWT;

class JWTPayload {
    public string $sub;
    
    public array $userData;
    
    public int $exp;
    
    public string $iss;
    
    public string $aud;
    
    public string $nbf;

    public string $iat;
    
    public string $jti;



    /**
     * This method build and JWT Payload
     * 
     * //(Subject): Identifies the subject of the token (for example, the id user).
     *  @param string $sub
     *  
     *  //Store user basic data to serve stateless application
     *  @param string $userData
     */
    public function __construct(string $sub, array $userData){
        $this->sub = $sub;
        $this->userData = $userData;
    }

    /**
     * (Expiration Time)
     * Specifies the token expiration timestamp.
     */
    public function setExp(int $exp){
        $this->exp = $exp;
    }

    /**
     * (Issuer)
     * Identify token sender
     */
    public function setIss(string $iss){
        $this->iss = $iss;
    }

    /**
     * (Audience)
     * Specifies intended recipients, like URL of application.
     */
    public function setAud(string $aud){
        $this->aud = $aud;
    }

    /**
     * (Not Before)
     * Specifies the moment from which the token becomes valid.
     */
    public function setNbf(string $nbf){
        $this->nbf = $nbf;
    }

    /**
     * (Issued At)
     * Indicates the time the token was issued.
     */
    public function setIat(string $iat){
        $this->iat = $iat;
    }

    /**
     * (JWT ID)
     * Provides a unique identifier for the token.
     */
    public function setJti(string $jti){
        $this->jti = $jti;
    }

}