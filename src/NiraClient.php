<?php

namespace AfromanSR\LaravelNiraApi;

use DateTime;
use DateTimeZone;
use Exception;
use Illuminate\Support\Str;
use SoapClient;
use SoapHeader;
use SoapVar;
use stdClass;

class NiraClient
{
    private $nira_wsdl;
    private $nira_server_path;
    private $nira_server;
    private $namespace;
    private $username, $password;
    private $soapClient;
    public $nonce;
    private $timestamp;
    public $created_with_colon;
    public $created_without_colon;
    private $packedNonce;

    public function __construct()
    {
        $this->username = config('nira.username');
        $this->password = config('nira.password');
        $this->nira_server_path = config('nira.server_path');
        $this->nira_server = config('nira.server');
        $this->namespace = config('nira.namespace');
        $this->timestamp = DateTime::createFromFormat('U.u', number_format(microtime(true), 3, '.', ''));
        $this->timestamp->setTimezone(new DateTimeZone('Africa/Kampala'));
        $now = $this->timestamp;
        $this->created_with_colon = substr($now->format('Y-m-d\TH:i:s.u'), 0, -3) . $now->format("P");
        $this->created_without_colon = substr($now->format('Y-m-d\TH:i:s.u'), 0, -3) . preg_replace("/\:/","", $now->format("P"));

        $this->initiateClient();
    }

    public function getNiraWsdl() {
        return dirname(__FILE__)."/nira.wsdl";
    }

    public function getPublicKeyPath() {
        return dirname(__FILE__)."/niragoug.crt";
    }

    public function initiateClient($enable_trace = TRUE )
    {
        $wsdl = $this->getNiraWsdl();
        $this->nira_server = "http://".$this->nira_server."/".$this->nira_server_path;

        $this->soapClient = new SoapClient($wsdl, array(
                'location' => "$this->nira_server",
                'uri'      => $this->namespace,
                'trace' => $enable_trace,
                'soap_version' => SOAP_1_1)
        );

        $auth = new stdClass();

        $xsd_string_namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        $auth->Username = new SoapVar($this->username, XSD_STRING, NULL, $xsd_string_namespace, NULL, $xsd_string_namespace);

        $password_digest = $this->generatePasswordDigest();

        $auth->Password = new SoapVar($password_digest, XSD_STRING, "PasswordDigest", $xsd_string_namespace, NULL, $xsd_string_namespace);
        $auth->Nonce    = new SoapVar($this->nonce, XSD_STRING, NULL, $xsd_string_namespace, NULL, $xsd_string_namespace);

        $auth->Created  = new SoapVar($this->created_with_colon, XSD_STRING, NULL, $xsd_string_namespace, NULL, $xsd_string_namespace);

        $uuT = new SoapVar($auth, SOAP_ENC_OBJECT, NULL, $xsd_string_namespace, 'UsernameToken', $xsd_string_namespace);

        $userToken = new stdClass();
        $userToken->UsernameToken = $uuT;

        $secHeaderValue=new SoapVar($userToken, SOAP_ENC_OBJECT, NULL, $xsd_string_namespace, 'Security', $xsd_string_namespace);
        $secHeader = new SoapHeader($xsd_string_namespace, 'UsernameToken', $uuT);

        $this->soapClient->__setSoapHeaders($secHeader);
    }

    /**
     * Generate password digest.
     *
     * Using the password directly may work also, but it's not secure to transmit it without encryption.
     * And anyway, at least with axis+wss4j, the nonce and timestamp are mandatory anyway.
     *
     * @return string   base64 encoded password digest
     */
    public function generatePasswordDigest()
    {
        $this->nonce = $this->getNonce();

        $packedNonce =   base64_decode($this->nonce);


        $packedTimestamp = pack('a*', utf8_encode($this->created_without_colon));

        $passwordhash_bytes =  sha1($this->password,TRUE);

        $hash = sha1($packedNonce . $this->created_without_colon . $passwordhash_bytes , TRUE);


        return  base64_encode($hash);

    }

    function getNonce($nonce = NULL): string
    {
        $my_nonce = NULL;
        $nonce_bytes = \random_bytes(16);

        if ($nonce === NULL) {
            $my_nonce = \base64_encode($nonce_bytes);
        }
        return $my_nonce;
    }

    //this is for creating a new password and encrypting it.
    function encryptData($string, $key_path)
    {

        if( !file_exists($key_path))
        {
            return FALSE;
        }

        $fp=fopen("$key_path","r");
        $pub_key=fread($fp,8192);
        fclose($fp);

        openssl_public_encrypt(utf8_encode($string),$crypttext, $pub_key );

        return base64_encode($crypttext);
    }

    function createNewPassword($new_password, $pub_key_path)
    {
        $new_password = $this->encryptData($new_password, $pub_key_path);
        $returnObj = new stdClass();

        try
        {
            $requestObj = new stdClass();
            $requestObj->newPassword = $new_password;

            $changePasswordRequest = new stdClass();
            $changePasswordRequest->request = $requestObj;

            $myObj = new SoapVar($changePasswordRequest, SOAP_ENC_OBJECT, NULL, $this->namespace, 'request', $this->namespace);


            $result = $this->soapClient->changePassword($myObj);

            $transactionStatus = $result->return->transactionStatus;
            if($transactionStatus->transactionStatus === "Error")
            {


                $returnObj->status = FALSE;
                $returnObj->message = $transactionStatus->error->message;
                $returnObj->accountDetails = NULL;
                $requestObj->responseObj = NULL;

                return $returnObj;
            }
            else
            {
                $requestObj->status = TRUE;
                $returnObj->message = "Ok";
                $returnObj->responseObj = $result;

                return $returnObj;

            }
            /*
                        echo "<br/>";
                        echo "REQUEST:<br/>" . htmlentities($this->soapClient->__getLastRequest()) . "<br/><br/>";

                        echo "RESPONSE:<br/>" . htmlentities( $this->soapClient->__getLastResponse()) . "<br/><br/>";
                        */
        } catch(Exception $ex) {
            $returnObj->status = FALSE;
            $returnObj->message = $ex->getMessage();
            $returnObj->accountDetails = NULL;
            $requestObj->responseObj = NULL;

            return $returnObj;

            /*
            print "<h5>ERROR </h5> <br/> ";
            $this->printScreen($ex);

            $last_request = $this->soapClient->__getLastRequest();
            if(!is_null($last_request))
            echo "REQUEST:<br/>" . htmlentities($last_request) . "<br/>";
            //echo "<br/>Response<br/>";
            echo "<br/>RESPONSE:<br/>" . htmlentities($this->soapClient->__getLastResponse()) . "<br/>";
            */
        }
    }

    public function getPerson($nin)
    {
        $returnObj = new stdClass();

        try
        {
            $requestObj = new stdClass();
            $requestObj->nationalId = $nin;
            $getPersonRequest = new stdClass();
            $getPersonRequest->request = $requestObj;
            $myObj = new SoapVar($getPersonRequest, SOAP_ENC_OBJECT, NULL, $this->namespace, 'request', $this->namespace);
            $getPersonResponse = $this->soapClient->getPerson($myObj);
            $transactionStatus = $getPersonResponse->return->transactionStatus;
            if($transactionStatus->transactionStatus === "Error") {
                $returnObj->status = FALSE;
                $returnObj->message = $transactionStatus->error->message;
                $returnObj->accountDetails = NULL;
                $requestObj->responseObj = NULL;
            } else {
                $returnObj->status = TRUE;
                $returnObj->message = $transactionStatus->transactionStatus;
                $returnObj->accountDetails = (object)['passwordDaysLeft' => $transactionStatus->passwordDaysLeft, "executionCost"=> $transactionStatus->executionCost];

                //getting person details
                $personObj = new stdClass();
                $personObj->nationalId = Str::upper($getPersonResponse->return->nationalId); //the nationId/NIN
                $personObj->surname = Str::upper($getPersonResponse->return->surname); //the surname of the person
                $personObj->givenNames = Str::upper($getPersonResponse->return->givenNames); //the given names. more like the first name
                $personObj->maidenNames = Str::upper($getPersonResponse->return->maidenNames); //the maiden names
                $personObj->previousSurnames = Str::upper($getPersonResponse->return->previousSurnames); //the previous Surnames
                $personObj->dateOfBirth = $getPersonResponse->return->dateOfBirth; //date of birth
                $personObj->dateOfBirthEstimated = $getPersonResponse->return->dateOfBirthEstimated; //the estimated date of Birth
                $personObj->gender = $getPersonResponse->return->gender; //the gender of the person
                $personObj->nationality = Str::upper($getPersonResponse->return->nationality); //the nationality of the person
                $personObj->livingStatus = Str::upper($getPersonResponse->return->livingStatus); //if the person is dead or alive
                $personObj->photo = property_exists($getPersonResponse->return, "photo") ? base64_encode($getPersonResponse->return->photo) : NULL; // if photo exists

                $returnObj->responseObj = $personObj;
            }

            return collect($returnObj);
        } catch(Exception $ex) {
            $returnObj->status = FALSE;
            $returnObj->message = $ex->getMessage();
            $returnObj->accountDetails = NULL;
            $returnObj->responseObj = NULL;

            return $returnObj;
        }
    }

    /**
     * This Function Verifies a person against NIRA.
     * NOTE: for this to work, you have to be authorized by NIRA to access this API method.
     */

    function verifyPerson($nationalId)
    {
        $returnObj = new stdClass();

        try {
            $requestObj = new stdClass();
            $requestObj->nationalId = $nationalId;

            $verifyPersonRequest = new stdClass();
            $verifyPersonRequest->request = $requestObj;

            $myObj = new SoapVar($verifyPersonRequest, SOAP_ENC_OBJECT, NULL, $this->namespace, 'request', $this->namespace);

            $verifyPersonResponse = $this->soapClient->verifyPerson($myObj);
            $transactionStatus = $verifyPersonResponse->return->transactionStatus;

            if(ucfirst($transactionStatus->transactionStatus) === "Error")
            {
                $returnObj->status = FALSE;
                $returnObj->message = $transactionStatus->error->message;
                $returnObj->accountDetails = NULL;
                $requestObj->responseObj = NULL;
            } else {
                $requestObj->status = TRUE;
                $returnObj->message = "Ok";
                $returnObj->responseObj = $verifyPersonResponse;

            }

            return $returnObj;
        } catch(Exception $ex) {
            $returnObj->status = FALSE;
            $returnObj->message = $ex->getMessage();
            $returnObj->responseObj = NULL;

            return $returnObj;
        }

    }

    /**
     * This Function Gets Voter Details from NIRA.
     * NOTE: for this to work, you have to be authorized by NIRA to access this API method.
     */

    function getVoterDetails($nationalId)
    {
        $returnObj = new stdClass();

        try
        {
            $requestObj = new stdClass();
            $requestObj->nationalId = $nationalId;

            $getVoterDetailsRequest = new stdClass();
            $getVoterDetailsRequest->request = $requestObj;

            $myObj = new SoapVar($getVoterDetailsRequest, SOAP_ENC_OBJECT, NULL, $this->namespace, 'request', $this->namespace);


            $getVoterDetailsResponse = $this->soapClient->getVoterDetails($myObj);

            $transactionStatus = $getVoterDetailsResponse->return->transactionStatus;


            if(ucfirst($transactionStatus->transactionStatus) === "Error")
            {
                $returnObj->status = FALSE;
                $returnObj->message = $transactionStatus->error->message;
                $returnObj->accountDetails = NULL;
                $requestObj->responseObj = NULL;

                return $returnObj;
            }
            else
            {
                $requestObj->status = TRUE;
                $returnObj->message = "Ok";
                $returnObj->responseObj = $getVoterDetailsResponse;

                return $returnObj;

            }


        }
        catch(Exception $ex)
        {
            $returnObj->status = FALSE;
            $returnObj->message = $ex->getMessage();
            $returnObj->responseObj = NULL;

            return $returnObj;


        }
    }

    function getPlaceOfBirth($nationalId)
    {

        $returnObj = new stdClass();

        try
        {
            $requestObj = new stdClass();
            $requestObj->nationalId = $nationalId;

            $getPlaceOfBirthRequest = new stdClass();
            $getPlaceOfBirthRequest->request = $requestObj;

            $myObj = new SoapVar($getPlaceOfBirthRequest, SOAP_ENC_OBJECT, NULL, $this->namespace, 'request', $this->namespace);


            $getPlaceOfBirthResponse = $this->soapClient->getPlaceOfBirth($myObj);

            $transactionStatus = $getPlaceOfBirthResponse->return->transactionStatus;


            if(ucfirst($transactionStatus->transactionStatus) === "Error")
            {
                $returnObj->status = FALSE;
                $returnObj->message = $transactionStatus->error->message;
                $returnObj->accountDetails = NULL;
                $requestObj->responseObj = NULL;

                return $returnObj;
            }
            else
            {
                $requestObj->status = TRUE;
                $returnObj->message = "Ok";
                $returnObj->responseObj = $getPlaceOfBirthResponse;

                return $returnObj;

            }


        }
        catch(Exception $ex)
        {
            $returnObj->status = FALSE;
            $returnObj->message = $ex->getMessage();
            $returnObj->responseObj = NULL;

            return $returnObj;


        }


    }

    function printScreen($obj)
    {
        echo "<pre>";
        var_dump($obj);
        echo "</pre>";
    }

    function create_byte_array($string){
        $array = array();
        foreach(str_split($string) as $char){
            array_push($array, sprintf("%02X", ord($char)));
        }
        //return $array;
        return implode(' ', $array);
    }
}

