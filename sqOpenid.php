<?php

/**
 * OpenID 2.0 Relay party
 *
 * @autor nbari - Oct 2012
 * @package slashQuery
 * @link http://openid.net/specs/openid-authentication-2_0.html
 * @license http://www.opensource.org/licenses/bsd-license.php
 */
class sqOpenID {

  /**
   * openid.dh_modulus - base64(btwoc(p))
   * Diffie-Hellman Key Exchange Default Value
   *
   * @see section 8.1.2 of specification
   */
  const OPENID_DH_MODULUS = '155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443';

  /**
   * openid.dh_gen - base64(btwoc(g))
   *
   * @see section 8.1.2 of specification
   */
  const OPENID_DH_GEN = 2;

  /**
   * ns
   *
   * @see section 5.1.2 of specification
   */
  const OPENID_NS_2_0 = 'http://specs.openid.net/auth/2.0';

  /**
   * Extensible Resource Descriptor documents.
   */
  const OPENID_NS_XRD = 'xri://$xrd*($v*2.0)';

  /**
   * identifier_select
   */
  const OPENID_IDENTIFIER_SELECT = 'http://specs.openid.net/auth/2.0/identifier_select';

  /**
   * OpenID Simple Registration extension.
   */
  const OPENID_NS_SREG = 'http://openid.net/extensions/sreg/1.1';

  /**
   * OpenID Attribute Exchange extension.
   *
   * @link http://openid.net/specs/openid-attribute-exchange-1_0.html
   */
  const OPENID_AX = 'http://openid.net/srv/ax/1.0';

  /**
   * URI Generic Syntax
   *
   * @link http://www.ietf.org/rfc/rfc3986.txt
   * @see Appendix B. Parsing a URI Reference with a Regular Expression
   */
  const URI_REGEX = '@^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?@';

  /**
   * URL to which the OP SHOULD return the User-Agent with the response
   * indicating the status of the request
   *
   * @var string
   */
  private $return_to;

  /**
   * URL pattern the OP SHOULD ask the end user to trust
   *
   * @var string
   */
  private $realm;

  /**
   * normalized into an Identifier
   *
   * @var string
   */
  private $identity;

  /**
   * The Claimed Identifier set after the discovery proccess
   *
   * @var string
   */
  private $claimed_id;

  /**
   * OP Endpoint URL
   *
   * @see 7.3.1. Discovered Information
   * @link http://openid.net/specs/openid-authentication-2_0.html#discovery
   * @var string
   */
  private $provider;

  /**
   * Set Max number of request to avoid endless redirections.
   *
   * @var int
   */
  private $max_requests = 5;

  /**
   * OpenID extensions
   *
   * @var array
   */
  private $service_types = array ();

  /**
   * XRI identifier
   *
   * @var boolean
   */
  private $xri = false;

  /**
   * curl Requests responses
   */
  private $headers, $body;

  /**
   * OP response
   *
   * @var array
   */
  private $response = array ();

  /**
   * AX <==> SREG
   * @var array
   */
  protected  $ax_to_sreg = array (
    'namePerson/friendly' => 'nickname',
    'contact/email' => 'email',
    'namePerson' => 'fullname',
    'birthDate' => 'dob',
    'person/gender' => 'gender',
    'contact/postalCode/home' => 'postcode',
    'contact/country/home' => 'country',
    'pref/language' => 'language',
    'pref/timezone' => 'timezone'
  );

  /**
   * required, optional and params used for sreg,ax
   */
  private $required = array(), $optional = array(), $params = array();

  /**
   * __construct
   *
   * @see http://openid.net/specs/openid-authentication-2_0.html#anchor27
   * @param string $host The realm OP SHOULD ask the end user to trust.
   */
  public function __construct($host = null) {
    if (PHP_SAPI === 'cli') {
      return;
    }

    if ($host) {
      $host = strpos( $host, '://' ) ? $host : ($this->usingSSL() ? "https://$host" : "http://$host");
    } else {
      $host = ($this->usingSSL() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'];
    }

    /* remove URI from host */
    if (($host_end = strpos( $host, '/', 8 )) !== false) {
      $host = substr( $host, 0, $host_end );
    }

    $this->realm = $host;

    /* remove all openid. arguments from url */
    $this->return_to = $host . rtrim( preg_replace( '#((?<=\?)|&)openid\.[^&]+#', '', $_SERVER['REQUEST_URI'] ), '?' );

    /* store $_GET + $_POST */
    $this->response = $_REQUEST;
  }

  /**
   * getResponse
   *
   * @param string $key
   * @return string/array $_REQUEST
   */
  public function getResponse($key = null) {
    if ($key) {
      return (array_key_exists( $key, $this->response ) && isset( $this->response[$key] )) ? $this->response[$key] : false;
    }
    return $this->response;
  }

  /**
   * usingSSL
   *
   * @return string/boolean
   */
  public function usingSSL() {
    return ((isset( $_SERVER['HTTPS'] ) && strtolower( $_SERVER['HTTPS'] ) == 'on') || (isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && strtolower( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) == 'https'));
  }

  /**
   * setIdentity - The end user's input MUST be normalized into an Identifier.
   *
   * @link http://openid.net/specs/openid-authentication-2_0.html#normalization
   * @param string $openid_identifier
   * @return sqOpenID
   */
  public function setIdentity($openid_identifier) {
    $oi = preg_replace( '#/+$#', '', stripslashes( trim( $openid_identifier ) ) );

    /**
     * If the URL contains a fragment part, it MUST be stripped off together
     * with the fragment delimiter character "#"
     *
     * @see 7.2. Normalization
     */
    $oi = strtok( $oi, '#' );

    if (preg_match( '#^xri:/*#i', $oi, $m )) {
      $this->xri = true;
      $oi = 'https://xri.net/' . substr( $oi, strlen( $m[0] ) );
    } elseif (preg_match( '#^[=@+$!(]#', $oi )) {
      $this->xri = true;
      $oi = 'https://xri.net/' . $oi;
    } elseif (preg_match( '#^https?://[^/]+$#i', $oi )) {
      $oi .= '/';
    } elseif (! preg_match( '#https?://#i', $oi )) {
      $oi = "http://$oi/";
    }

    /**
     * set the identity
     */
    $this->identity = $this->normalizeURL($oi);

    /**
     * return this so it can be chainable
     */
    return $this;
  }

  /**
   * set required params
   * @see OpenID Attribute Exchange 1.0 - Final
   */
  public function required() {
    $this->required = array_flip(func_get_args());
  }

  /**
   * set optional params
   * @see OpenID Attribute Exchange 1.0 - Final
   */
  public function optional() {
    $this->optional = array_flip(func_get_args());
  }

  /**
   * getClaimedID
   *
   * The Claimed Identifier in a successful authentication response SHOULD be
   * used by the Relying Party as a key for local storage of information about
   * the user.
   *
   * @return string openid.claimed_id
   */
  public function getClaimedID() {
    return $this->claimed_id;
  }

  /**
   * request
   *
   * @param string $url
   * @return boolean
   */
  protected function request($url, $xrds = true, $method = 'GET', $params = array()) {
    $params = http_build_query( $params, '', '&' );
    $ch = curl_init( $url . ($method == 'GET' && $params ? '?' . $params : '') );
    curl_setopt( $ch, CURLOPT_USERAGENT, __CLASS__ . ' - OpenID v2' );
    curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
    curl_setopt( $ch, CURLOPT_HEADER, false );
    curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
    if ($method == 'POST') {
      curl_setopt( $ch, CURLOPT_POST, true );
      curl_setopt( $ch, CURLOPT_POSTFIELDS, $params );
    } else {
      curl_setopt( $ch, CURLOPT_HEADER, true );
      curl_setopt( $ch, CURLOPT_HTTPGET, true );
    }
    if ($xrds) {
      curl_setopt( $ch, CURLOPT_HTTPHEADER, array (
          'Accept: application/xrds+xml, */*'
      ) );
    }

    $response = curl_exec( $ch );

    if ($method == 'GET') {
      $header_size = curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
      $header = substr( $response, 0, $header_size );
      $this->body = substr( $response, $header_size );
    } else {
      $header = $response;
    }

    $headers = array ();
    foreach ( explode( "\n", $header ) as $h ) {
      $pos = strpos( $h, ':' );
      if ($pos !== false) {
        $name = strtolower( trim( substr( $h, 0, $pos ) ) );
        $headers[$name] = trim( substr( $h, $pos + 1 ) );
      }
    }

    $this->headers = $headers;

    $effective_url = curl_getinfo( $ch, CURLINFO_EFFECTIVE_URL );
    if ($effective_url != $url) {
      $this->identity = $effective_url;
    }

    if (curl_errno( $ch )) {
      return false;
    }
    return true;
  }

  /**
   * Discover
   *
   * Discovery is the process where the Relying Party uses the
   * Identifier to look up ("discover") the necessary information for initiating
   * requests.
   *
   * @see http://openid.net/specs/openid-authentication-2_0.html#discovery
   * @return boolean
   */
  public function Discover() {
    return $this->DiscoverYadis() ?  : ($this->DiscoverHTML() ?  : false);
  }

  /**
   * DiscoverYadis
   *
   * @see 7.3.2. XRDS-Based Discovery
   * @return boolean
   */
  protected function DiscoverYadis($url = null) {
    /* decrease max_requests -1 */
    $this->max_requests --;

    $url = isset( $url ) ? $url : $this->identity;

    if ($this->request( $url ) && $this->max_requests) {

      if (isset( $this->headers['content-type'] ) && (strpos( $this->headers['content-type'], 'application/xrds+xml' ) !== false)) {
        $services = array ();
        try {
          $xml = @new SimpleXMLElement( $this->body );
          foreach ( $xml->children( self::OPENID_NS_XRD )->XRD as $xrd ) {
            foreach ( $xrd->children( self::OPENID_NS_XRD )->Service as $service_element ) {
              $service = array (
                  'priority' => $service_element->attributes()->priority ? ( int ) $service_element->attributes()->priority : PHP_INT_MAX,
                  'types' => array (),
                  'uri' => ( string ) $service_element->URI,
                  'identity' => ( string ) $service_element->LocalID ?  : false
              );
              /**
               *
               * @see 7.3.2.3. XRI and the CanonicalID Element
               */
              if ($this->xri) {
                $service['canonicalid'] = ( string ) $xrd->children( self::OPENID_NS_XRD )->CanonicalID;
              }
              foreach ( $service_element->Type as $type ) {
                $service['types'][] = ( string ) $type;
              }
              /* search for openid v2 ns */
              $ns = preg_quote( self::OPENID_NS_2_0, '#' );
              if (! preg_grep( "#$ns#", $service['types'] )) {
                continue;
              }
              $services[] = $service;
            }
          }
        } catch ( Exception $e ) {
          return false;
        }

        if (empty( $services )) {
          return false;
        }
        /**
         * Extensible Resource Identifier (XRI) Resolution Version 2.0, section
         * 4.3.3:
         * Find the service with the highest priority (lowest integer value).
         * If there is a tie, select a random one, not just the first in the XML
         * document.
         */
        shuffle( $services );
        $selected_service = NULL;
        $selected_type_priority = FALSE;
        $type_priority = 0;

        foreach ( $services as $service ) {
          if (! empty( $service['uri'] )) {
            if (in_array( self::OPENID_NS_2_0 . '/server', $service['types'] )) {
              $type_priority = 1;
            } elseif (in_array( self::OPENID_NS_2_0 . '/signon', $service['types'] )) {
              $type_priority = 2;
            }

            if ($type_priority && (! $selected_service || $type_priority < $selected_type_priority
                                                       || ($type_priority == $selected_type_priority && $service['priority'] < $selected_service['priority']))) {
              $selected_service = $service;
              $selected_type_priority = $type_priority;
            }
          }
        }

        if ($selected_service) {
          $this->provider = $selected_service['uri'];
          if ($selected_type_priority == 1) {
            /**
             * If the end user entered an OP Identifier, there is no Claimed
             * Identifier.
             * For the purposes of making OpenID Authentication requests, the
             * value "http://specs.openid.net/auth/2.0/identifier_select" MUST
             * be used as both the Claimed Identifier and the OP-Local
             * Identifier when an OP Identifier is entered.
             *
             * @see 7.3.1. Discovered Information
             */
            $this->claimed_id = $this->identity = self::OPENID_IDENTIFIER_SELECT;
          } elseif ($selected_service['identity']) {
            /**
             * <xrd:LocalID> tag (optional) whose text content is the
             * OP-Local Identifier.
             *
             * @see 7.3.2.1.2. Claimed Identifier Element
             */
            $this->claimed_id = $this->identity = $selected_service['identity'];
          } elseif ($this->xri && ! empty( $selected_service['canonicalid'] )) {
            $this->claimed_id = $this->identity = $selected_service['canonicalid'];
          } else {
            $this->claimed_id = $this->identity;
          }
          $this->service_types = $selected_service['types'];
          return true;
        } else {
          return false;
        }
      } elseif (isset( $this->headers['x-xrds-location'] )) {
        return $this->DiscoverYadis( $this->headers['x-xrds-location'] );
      } else {
        @$html_dom = DOMDocument::loadHTML( $this->body );
        if ($html_dom) {
          $html_element = simplexml_import_dom( $html_dom );
          foreach ( $html_element->head->meta as $meta ) {
            // The http-equiv attribute is case-insensitive.
            if (strtolower( trim( $meta['http-equiv'] ) ) == 'x-xrds-location') {
              return $this->DiscoverYadis( trim( $meta['content'] ) );
            }
          }
        }
        return false;
      }
    } else {
      return false;
    }
  }

  /**
   * DiscoverHTML
   *
   * @see 7.3.3. HTML-Based Discovery
   * @return boolean
   */
  protected function DiscoverHTML() {
    if ($this->parseHTML( $this->body )) {
      return true;
    } else {
      return $this->request( $this->identity, false ) ? $this->parseHTML( $this->body ) : false;
    }
  }

  /**
   * parseHTML
   * @retun boolean
   */
  protected function parseHTML($body) {
    @$html_dom = DOMDocument::loadHTML( $body );
    if ($html_dom) {
      $html_element = simplexml_import_dom( $html_dom );
      foreach ( $html_element->head->link as $link ) {
        if (preg_match( '#(\s|^)openid2.provider(\s|$)#i', $link['rel'] )) {
          $this->provider = trim( $link['href'] );
        }
        if (preg_match( '#(\s|^)openid2.local_id(\s|$)#i', $link['rel'] )) {
          $this->identity = $this->claimed_id = trim( $link['href'] );
        }
      }
      /**
       * The protocol version when HTML discovery is performed is
       * "http://specs.openid.net/auth/2.0/signon".
       */
      if (! $this->claimed_id) {
        $this->claimed_id = $this->identity;
      }
      return ($this->provider) ? true : false;
    }
    return false;
  }

  /**
   * Auth
   *
   * @see 9.1. Request Parameters
   * @link http://openid.net/specs/openid-authentication-2_0.html#anchor27
   */
  public function Auth() {
    $this->params = array (
        'openid.ns' => self::OPENID_NS_2_0,
        'openid.mode' => 'checkid_setup',
        'openid.claimed_id' => $this->claimed_id,
        'openid.identity' => $this->identity,
        'openid.return_to' => $this->return_to,
        'openid.realm' => $this->realm
    );

    if ($this->required || $this->optional) {
      $this->sregParams();
      $this->axParams();
    }

    /**
     * Association data stored in a session
     */
    if (! isset( $_SESSION )) {
      session_start();

      if ($mac_key = $this->associate()) {
        /**
         * A handle for an association between the Relying Party and the OP that
         * SHOULD be used to sign the response.
         * Note: If no association handle is sent, the transaction will take
         * place in Stateless Mode.
         */
        $this->params['openid.assoc_handle'] = $this->headers['assoc_handle'];

        /**
         * store the association_handle and mac_key (shared secret)
         */
        $_SESSION['openid.assoc_handle'] = $this->headers['assoc_handle'];
        $_SESSION['openid.mac_key'] = $mac_key;
        $_SESSION['openid.claimed_id'] = $this->claimed_id;
      }
    }

    $s = strpos( $this->provider, '?' ) ? '&' : '?';
    $url = $this->provider . $s . http_build_query( $this->params, '', '&' );

    /**
     * redirect to OP Endpoint URL
     */
    header( "Location: $url" );
  }

  /**
   * sregParams
   *
   * @link http://openid.net/specs/openid-simple-registration-extension-1_0.html
   * @see 3. Request Format
   */
  protected function sregParams() {
    $this->params['openid.ns.sreg'] = self::OPENID_NS_SREG;
    if ($this->required) {
      $this->params['openid.sreg.required'] = implode(',',  array_intersect_key( $this->ax_to_sreg,  $this->required ) );
    }
    if ($this->optional) {
      $this->params['openid.sreg.optional'] = implode(',',  array_intersect_key( $this->ax_to_sreg,  $this->optional ) );
    }
  }

  /**
   * AX parameters
   *
   * @link http://openid.net/specs/openid-attribute-exchange-1_0.html
   * @see 5.  Fetch Message
   */
  protected function axParams() {
    $this->params['openid.ns.ax'] = self::OPENID_AX;
    $this->params['openid.ax.mode'] = 'fetch_request';

    $aliases = array();
    $required = array();
    $optional = array();
    /**
     * $this->required contains an array of required AX parameters
     * $this->optional contains an array of optional AX parameters.
     */
    foreach ( array ('required', 'optional') as $type ) {
      foreach ( $this->$type as $path => $key ) {
        $alias = strtr($path, '/', '_');
        $aliases[$alias] = 'http://axschema.org/' . $path;
        ${$type}[] = $alias;
      }
    }
    foreach ( $aliases as $alias => $ns ) {
      $this->params['openid.ax.type.' . $alias] = $ns;
    }
    if ($required) {
      $this->params['openid.ax.required'] = implode( ',', $required );
    }
    if ($optional) {
      $this->params['openid.ax.if_available'] = implode( ',', $optional );
    }
  }

  /**
   * validate
   *
   * @return boolean
   */
  public function validate() {
    if ($this->getResponse( 'openid_user_setup_url' )) {
      return false;
    }

    if ($this->getResponse( 'openid_mode' ) != 'id_res') {
      return false;
    }

    if ($this->getResponse( 'openid_return_to' ) != $this->return_to) {
      return false;
    }

    if (!$this->getResponse(('openid_claimed_id'))) {
      return false;
    }

    $this->identity = $this->claimed_id = $this->normalizeURL( $this->getResponse( 'openid_claimed_id' ) );

    /**
     * check for association data in sessions if not fallback to stateless mode
     */
    if (! isset( $_SESSION )) {
      session_start();
    }
    if (isset( $_SESSION['openid.assoc_handle'], $_SESSION['openid.mac_key'], $_SESSION['openid.claimed_id'] )) {

      /**
       * The Claimed Identifier. "openid.claimed_id" and "openid.identity"
       * SHALL be either both present or both absent.
       */
      if ( !$this->getResponse('openid_claimed_id') && !$this->getResponse(('openid_identity')) ) {
        return false;
      }

      /**
       * Verify that openid_sig matches signed parameters in openid_signed
       * This list MUST contain at least "op_endpoint", "return_to"
       * "response_nonce" and "assoc_handle", and if present in the response,
       * "claimed_id" and "identity".
       */
      $must = array (
          'op_endpoint',
          'return_to',
          'response_nonce',
          'assoc_handle',
          'claimed_id',
          'identity'
        );

      $signed = explode( ',', $this->getResponse( 'openid_signed' ) );

      /**
       * verify that open_signed has the 'must' parameters
       */
      if (count( array_intersect( $must, $signed ) ) !== count( $must )) {
        return false;
      }

      /**
       * When the Relying Party checks the signature on an assertion, the
       * Relying Party SHOULD ensure that an assertion has not yet been accepted
       * with the same value for "openid.response_nonce" from the same
       * OP Endpoint URL.
       *
       * @see 11.3. Checking the Nonce
       */
      if (isset( $_SESSION['openid.response_nonce'] ) && $_SESSION['openid.response_nonce'] == $this->getResponse( 'openid_response_nonce' )) {
        return false;
      } else {
        $_SESSION['openid.response_nonce'] = $this->getResponse( 'openid_response_nonce' );
      }

      if ($_SESSION['openid.claimed_id'] != self::OPENID_IDENTIFIER_SELECT) {
        if ($_SESSION['openid.claimed_id'] != strtok($this->claimed_id, '#')) {
          return false;
        }
      }

      /**
       * prepare fiels to sign
       *
       * @see 6. Generating Signatures
       */
      $tokens = '';
      foreach ( $signed as $key ) {
        $tokens .= sprintf( "%s:%s\n", $key, $this->getResponse( 'openid_' . strtr( $key, '.', '_' ) ) );
      }

      /**
       * @see 6.2. Signature Algorithms
       */
      $signature = base64_encode( hash_hmac( 'sha256', $tokens, $_SESSION['openid.mac_key'], true ) );

      /**
       * check if signatures match
       *
       * @return boolean
       */
      return $this->getResponse( 'openid_sig' ) === $signature;
    }

    /**
     * Stateless 'dumb' mode needs to found again the OP Endpoint URL.
     */
    $this->Discover();

    /**
     * @see 11.4.2.1. Request Parameters Exact copies of all fields from the
     * authentication response, except for "openid.mode".
     */
    $params = array ();
    foreach ( $this->getResponse() as $key => $value ) {
      /* replace _ with . openid.* */
      $params[preg_replace( '#_#', '.', $key, 1 )] = $value;
    }
    $params['openid.mode'] = 'check_authentication';

    $this->request( $this->provider, false, 'POST', $params );

    return (isset( $this->headers['is_valid'] ) && $this->headers['is_valid'] == 'true') ? true : false;
  }

  /**
   * associate
   *
   * The Relying Party and the OP establish an association -- a shared secret
   * established using Diffie-Hellman Key Exchange [RFC2631].
   *
   * @see 8. Establishing Associations
   */
  protected function associate() {
    $private_key = gmp_random(16);
    $public_key = base64_encode($this->btwocEncode(gmp_strval(gmp_powm(self::OPENID_DH_GEN, $private_key, self::OPENID_DH_MODULUS))));
    /**
     *
     * @see 8.1.1. Common Request Parameters
     */
    $params = array (
        'openid.ns' => self::OPENID_NS_2_0,
        'openid.mode' => 'associate',
        'openid.assoc_type' => 'HMAC-SHA256',
        'openid.session_type' => 'DH-SHA256',
        'openid.dh_consumer_public' => $public_key
    );

    if ($this->request( $this->provider, false, 'POST', $params )) {
      if (isset( $this->headers['dh_server_public'], $this->headers['enc_mac_key'] )) {
        $dh_server_public = base64_decode( $this->headers['dh_server_public'] );
        $enc_mac_key = $this->headers['enc_mac_key'];

        $ZZ = $this->btwocEncode(gmp_strval(gmp_powm($this->btwocDecode($dh_server_public), $private_key, self::OPENID_DH_MODULUS)));
        /**
         * decrypt & return the mac_key (shared secret)
         */
        return $this->openidXOR( hash( 'sha256', $ZZ, true ), base64_decode( $enc_mac_key ) );
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  /**
   * btwocEncode
   *
   * @see 4.2. Integer Representations
   * @param int $n
   * @return big-endian two's complement representation
   */
  public function btwocEncode($n) {
    $cmp = gmp_cmp( $n, 0 );

    if ($cmp == 0) {
      return "\x00";
    }

    $bytes = array ();

    while ( gmp_cmp( $n, 0 ) > 0 ) {
      array_unshift( $bytes, gmp_mod( $n, 256 ) );
      $n = gmp_div( $n, pow( 2, 8 ) );
    }

    if ($bytes && ($bytes[0] > 127)) {
      array_unshift( $bytes, 0 );
    }

    $string = '';
    foreach ( $bytes as $byte ) {
      $string .= pack( 'C', $byte );
    }

    return $string;
  }

  /**
   * btwocDecode
   *
   * @see 4.2. Integer Representations
   * @param string $str
   * @return Base 10 number
   */
  public function btwocDecode($str) {
    $bytes = array_merge( unpack( 'C*', $str ) );
    $n = 0;

    foreach ( $bytes as $byte ) {
      $n = gmp_mul( $n, pow( 2, 8 ) );
      $n = gmp_add( $n, $byte );
    }
    return gmp_strval( $n );
  }

  /**
   * openidXOR
   */
  public function openidXOR($x, $y) {
    $a = '';
    for ($i = 0; $i < strlen( $y ); $i ++) {
      $a .= $x[$i] ^ $y[$i];
    }
    return $a;
  }

  /**
   * normalizeURL - parse a URI Reference with a Regular Expression
   *
   * @see rfc3986
   * @return array
   */
  public function normalizeURL($uri) {
    $parts = array (
        'scheme' => '',
        'host' => '',
        'port' => '',
        'user' => '',
        'pass' => '',
        'path' => '',
        'query' => '',
        'fragment' => ''
    );

    preg_match( self::URI_REGEX, $uri, $matches );

    if (array_key_exists( 2, $matches )) $parts['scheme'] = strtolower($matches[2]);
    if (array_key_exists( 4, $matches )) $authority = $matches[4];
    if (array_key_exists( 5, $matches )) $parts['path'] = $matches[5];
    if (array_key_exists( 7, $matches )) $parts['query'] = $matches[7];
    if (array_key_exists( 9, $matches )) $parts['fragment'] = $matches[9];

    /* Extract username, password, host and port from authority */
    preg_match('"(([^:@]*)(:([^:@]*))?@)?([^:]*)(:(.*))?"', $authority, $matches);

    if (array_key_exists( 2, $matches )) $parts['user'] = $matches[2];
    if (array_key_exists( 4, $matches )) $parts['pass'] = $matches[4];
    if (array_key_exists( 5, $matches )) $parts['host'] = strtolower($matches[5]);
    if (array_key_exists( 7, $matches )) $parts['port'] = $matches[7];

    $url = $parts['scheme'] . '://' .
          (empty( $parts['user'] ) ? '' : (empty( $parts['pass'] ) ? "{$parts['user']}@" : "{$parts['user']}:{$parts['pass']}@")) .
          $parts['host'] .
          (empty( $parts['port'] ) ? '' : ":{$parts['port']}") .
          (empty( $parts['path'] ) ? '' : $parts['path']) .
          (empty( $parts['query'] ) ? '' : "?{$parts['query']}") .
          (empty( $parts['fragment'] ) ? '' : "#{$parts['fragment']}");

    return $url;
  }

  /**
   * getAxAttributes
   *
   * @version LightOpenID
   * @return array
   */
  public function getAxAttributes() {
    $alias = null;
    if ($this->getResponse('openid_ns_ax') && $this->getResponse('openid_ns_ax') != self::OPENID_AX) { // It's the most likely case, so we'll check it before
      $alias = 'ax';
    } else {
      // 'ax' prefix is either undefined, or points to another extension,
      // so we search for another prefix
      foreach ( $this->getResponse() as $key => $val ) {
        if (substr( $key, 0, strlen( 'openid_ns_' ) ) == 'openid_ns_' && $val == self::OPENID_AX) {
          $alias = substr( $key, strlen( 'openid_ns_' ) );
          break;
        }
      }
    }
    if (! $alias) {
      // An alias for AX schema has not been found,
      // so there is no AX data in the OP's response
      return array ();
    }

    $attributes = array ();
    foreach ( explode( ',', $this->getResponse('openid_signed') ) as $key ) {
      $keyMatch = $alias . '.value.';
      if (substr( $key, 0, strlen( $keyMatch ) ) != $keyMatch) {
        continue;
      }
      $key = substr( $key, strlen( $keyMatch ) );
      if (! $this->getResponse('openid_' . $alias . '_type_' . $key)) {
        // OP is breaking the spec by returning a field without
        // associated ns. This shouldn't happen, but it's better
        // to check, than cause an E_NOTICE.
        continue;
      }
      $value = $this->getResponse('openid_' . $alias . '_value_' . $key);
      $key = substr( $this->getResponse('openid_' . $alias . '_type_' . $key), strlen( 'http://axschema.org/' ) );

      $attributes[$key] = $value;
    }
    return $attributes;
  }

  /**
   * getSregAttributes
   *
   * @version LightOpenID
   * @return array
   */
  public function getSregAttributes() {
    $attributes = array ();
    $sreg_to_ax = array_flip( $this->ax_to_sreg );
    foreach ( explode( ',', $this->getResponse('openid_signed')) as $key ) {
      $keyMatch = 'sreg.';
      if (substr( $key, 0, strlen( $keyMatch ) ) != $keyMatch) {
        continue;
      }
      $key = substr( $key, strlen( $keyMatch ) );
      if (! isset( $sreg_to_ax[$key] )) {
        // The field name isn't part of the SREG spec, so we ignore it.
        continue;
      }
      $attributes[$sreg_to_ax[$key]] = $this->getResponse('openid_sreg_' . $key);
    }
    return $attributes;
  }

  /**
   * Gets AX/SREG attributes provided by OP.
   * should be used only after successful validaton.
   * Note that it does not guarantee that any of the required/optional
   * parameters will be present, or that there will be no other attributes
   * besides those specified. In other words. OP may provide whatever
   * information it wants to.
   *
   * @version LightOpenID
   * @return Array Array of attributes with keys being the AX schema names,
   */
  public function getAttributes() {
    return $this->getAxAttributes() + $this->getSregAttributes();
  }

}

?>