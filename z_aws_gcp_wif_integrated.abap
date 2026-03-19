REPORT z_aws_gcp_wif_integrated.

*----------------------------------------------------------------------*
* DATA STRUCTURES 752
*----------------------------------------------------------------------*
TYPES: BEGIN OF ty_aws_creds,
         accesskeyid     TYPE string,
         secretaccesskey TYPE string,
         token           TYPE string,
       END OF ty_aws_creds.

DATA: gs_aws_creds TYPE ty_aws_creds.

*----------------------------------------------------------------------*
* SELECTION SCREEN
*----------------------------------------------------------------------*
SELECTION-SCREEN BEGIN OF BLOCK b1 WITH FRAME TITLE TEXT-001.
  PARAMETERS: rb_test  RADIOBUTTON GROUP grp1 DEFAULT 'X',
              rb_token RADIOBUTTON GROUP grp1.
SELECTION-SCREEN END OF BLOCK b1.

SELECTION-SCREEN BEGIN OF BLOCK b2 WITH FRAME TITLE TEXT-002.
  PARAMETERS: p_prjnum TYPE string DEFAULT '903024777662' MODIF ID wif,
              p_poolid TYPE string DEFAULT 'dla-aws-erp' MODIF ID wif,
              p_provid TYPE string DEFAULT 'dla-aws-erp-provider' MODIF ID wif,
              p_s_acct TYPE string DEFAULT 'dla-aws-test-sa@psosap-il5-1772997642.iam.gserviceaccount.com' MODIF ID wif.
SELECTION-SCREEN END OF BLOCK b2.

*----------------------------------------------------------------------*
* CLASS DEFINITION
*----------------------------------------------------------------------*
CLASS lcl_wif_manager DEFINITION.
  PUBLIC SECTION.
    METHODS run_test.
    METHODS run_wif_flow.

  PRIVATE SECTION.
    METHODS fetch_dynamic_aws_creds RETURNING VALUE(rv_success) TYPE abap_bool.
    METHODS generate_aws_sts_token  IMPORTING iv_resource TYPE string RETURNING VALUE(rv_json_token) TYPE string.
    METHODS get_federated_token     IMPORTING iv_subject_token TYPE string iv_audience TYPE string RETURNING VALUE(rv_token) TYPE string.
    METHODS get_gcp_access_token    IMPORTING iv_fed_token TYPE string RETURNING VALUE(rv_token) TYPE string.
    
    " Helpers
    METHODS hash_sha256             IMPORTING iv_data TYPE string RETURNING VALUE(rv_hash) TYPE string.
    METHODS hmac_sha256             IMPORTING iv_key TYPE xstring iv_data TYPE string RETURNING VALUE(rv_hmac) TYPE xstring.
    METHODS string_to_xstring       IMPORTING iv_str TYPE string RETURNING VALUE(rv_xstr) TYPE xstring.
ENDCLASS.

*----------------------------------------------------------------------*
* CLASS IMPLEMENTATION
*----------------------------------------------------------------------*
CLASS lcl_wif_manager IMPLEMENTATION.

  METHOD run_test.
    DATA: lo_http TYPE REF TO if_http_client.
    WRITE: / '--- Testing AWS Metadata Connectivity ---'.
    cl_http_client=>create_by_url( EXPORTING url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' IMPORTING client = lo_http ).
    lo_http->send( timeout = 5 ). lo_http->receive( ).
    IF lo_http->response->get_cdata( ) IS NOT INITIAL.
      WRITE: / 'STATUS: SUCCESS', / 'Detected Role:', lo_http->response->get_cdata( ).
    ELSE.
      WRITE: / 'STATUS: FAILED. Check SMICM proxy/RZ11 no_proxy settings.'.
    ENDIF.
    lo_http->close( ).
  ENDMETHOD.

  METHOD run_wif_flow.
    WRITE: / '--- Starting WIF Token Exchange ---'.
    
    IF fetch_dynamic_aws_creds( ) = abap_false. 
      RETURN. 
    ENDIF.

    WRITE: / 'SUCCESS: Fetched AWS Credentials.'.
    WRITE: / 'AWS Access Key ID:', gs_aws_creds-accesskeyid.
    WRITE: / '-----------------------------------------'.

    DATA(lv_audience) = |//iam.googleapis.com/projects/{ p_prjnum }/locations/global/workloadIdentityPools/{ p_poolid }/providers/{ p_provid }|.
    
    " STEP 1: Generate Subject Token
    DATA(lv_subj) = generate_aws_sts_token( lv_audience ).
    WRITE: / 'STEP 1: AWS STS Subject Token Generated:'.
    WRITE: / lv_subj.
    WRITE: / '-----------------------------------------'.

    " STEP 2: Get Federated Token
    DATA(lv_fed)  = get_federated_token( iv_subject_token = lv_subj iv_audience = lv_audience ).
    IF lv_fed IS INITIAL.
      WRITE: / 'FAILED: Could not get Federated Token.'. 
      RETURN.
    ENDIF.
    WRITE: / 'STEP 2: GCP Federated Token Retrieved:'.
    WRITE: / lv_fed.
    WRITE: / '-----------------------------------------'.

    " STEP 3: Get Service Account Access Token
    DATA(lv_bq) = get_gcp_access_token( lv_fed ).
    IF lv_bq IS NOT INITIAL.
      WRITE: / 'STEP 3: SUCCESS - BigQuery Access Token Generated:'.
      WRITE: / lv_bq.
    ELSE.
      WRITE: / 'FAILED: Could not impersonate Service Account.'.
    ENDIF.
    WRITE: / '-----------------------------------------'.
    
  ENDMETHOD.

  METHOD fetch_dynamic_aws_creds.
    DATA: lo_http TYPE REF TO if_http_client, lv_imds_token TYPE string, lv_role TYPE string.
    
    cl_http_client=>create_by_url( EXPORTING url = 'http://169.254.169.254/latest/api/token' IMPORTING client = lo_http ).
    lo_http->request->set_method( 'PUT' ).
    lo_http->request->set_header_field( name = 'x-aws-ec2-metadata-token-ttl-seconds' value = '21600' ).
    lo_http->send( ). lo_http->receive( ).
    lv_imds_token = lo_http->response->get_cdata( ). lo_http->close( ).

    " FIX: Removed inline return value and split the logic
    IF lv_imds_token IS INITIAL.
       WRITE: / 'ERROR: IMDSv2 Token missing.'. 
       rv_success = abap_false.
       RETURN.
    ENDIF.

    cl_http_client=>create_by_url( EXPORTING url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' IMPORTING client = lo_http ).
    lo_http->request->set_header_field( name = 'x-aws-ec2-metadata-token' value = lv_imds_token ).
    lo_http->send( ). lo_http->receive( ).
    lv_role = lo_http->response->get_cdata( ). lo_http->close( ).

    cl_http_client=>create_by_url( EXPORTING url = |http://169.254.169.254/latest/meta-data/iam/security-credentials/{ lv_role }| IMPORTING client = lo_http ).
    lo_http->request->set_header_field( name = 'x-aws-ec2-metadata-token' value = lv_imds_token ).
    lo_http->send( ). lo_http->receive( ).
    /ui2/cl_json=>deserialize( EXPORTING json = lo_http->response->get_cdata( ) CHANGING data = gs_aws_creds ).
    lo_http->close( ).
    rv_success = abap_true.
  ENDMETHOD.

  METHOD generate_aws_sts_token.
    DATA: lv_ts   TYPE timestamp,
          lv_date TYPE d,
          lv_time TYPE t,
          lv_tstr TYPE string.

    " FIX: Manual Timestamp formatting (avoids string offsets entirely)
    GET TIME STAMP FIELD lv_ts.
    CONVERT TIME STAMP lv_ts TIME ZONE 'UTC' INTO DATE lv_date TIME lv_time.
    
    " AWS requires ISO8601 basic format: YYYYMMDDTHHMMSSZ
    lv_tstr = |{ lv_date }T{ lv_time }Z|.
   

    *DATA(lv_scope) = |{ lv_date }/us-east-1/sts/aws4_request|.
     DATA(lv_scope) = |{ lv_date }/us-gov-west-1/sts/aws4_request|.
    *DATA(lv_can_headers) = |host:sts.amazonaws.com\nx-amz-date:{ lv_tstr }\n| &&
                           |x-amz-security-token:{ gs_aws_creds-token }\nx-goog-cloud-target-resource:{ iv_resource }\n|.
    DATA(lv_can_headers) = |host:sts.us-gov-west-1.amazonaws.com\nx-amz-date:{ lv_tstr }\n| &&
                           |x-amz-security-token:{ gs_aws_creds-token }\nx-goog-cloud-target-resource:{ iv_resource }\n|.

    DATA(lv_signed_hdrs) = 'host;x-amz-date;x-amz-security-token;x-goog-cloud-target-resource'.
    
    " Use backticks ` ` for an empty string literal to satisfy strict typing
    DATA(lv_can_req) = |POST\n/\nAction=GetCallerIdentity&Version=2011-06-15\n{ lv_can_headers }\n{ lv_signed_hdrs }\n{ hash_sha256( ` ` ) }|.
    DATA(lv_sts) = |AWS4-HMAC-SHA256\n{ lv_tstr }\n{ lv_scope }\n{ hash_sha256( lv_can_req ) }|.

    DATA(lv_ks) = string_to_xstring( 'AWS4' && gs_aws_creds-secretaccesskey ).
    DATA(lv_kd) = hmac_sha256( iv_key = lv_ks iv_data = |{ lv_date }| ).
    *DATA(lv_kr) = hmac_sha256( iv_key = lv_kd iv_data = 'us-east-1' ).
      DATA(lv_kr) = hmac_sha256( iv_key = lv_kd iv_data = 'us-gov-west-1' ).

    DATA(lv_ki) = hmac_sha256( iv_key = lv_kr iv_data = 'sts' ).
    DATA(lv_kn) = hmac_sha256( iv_key = lv_ki iv_data = 'aws4_request' ).

    DATA(lv_sig) = to_lower( |{ hmac_sha256( iv_key = lv_kn iv_data = lv_sts ) }| ).
    DATA(lv_auth) = |AWS4-HMAC-SHA256 Credential={ gs_aws_creds-accesskeyid }/{ lv_scope }, SignedHeaders={ lv_signed_hdrs }, Signature={ lv_sig }|.

    *DATA(lv_json) = |\{"url":"https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15","method":"POST","headers":[| &&
    DATA(lv_json) = |\{"url":"https://sts.us-gov-west-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15","method":"POST","headers":[| &&
                    |\{"key":"x-amz-date","value":"{ lv_tstr }"\},| &&
                    |\{"key":"x-amz-security-token","value":"{ gs_aws_creds-token }"\},| &&
                    |\{"key":"x-goog-cloud-target-resource","value":"{ iv_resource }"\},| &&
                    |\{"key":"Authorization","value":"{ lv_auth }"\}]\}|.
    rv_json_token = cl_http_utility=>escape_url( lv_json ).
  ENDMETHOD.

  METHOD get_federated_token.
    DATA: lo_h TYPE REF TO if_http_client.
    cl_http_client=>create_by_url( EXPORTING url = 'https://sts.googleapis.com/v1/token' IMPORTING client = lo_h ).
    lo_h->request->set_method( 'POST' ).
    lo_h->request->set_header_field( name = 'Content-Type' value = 'application/json' ).
    lo_h->request->set_cdata( |\{"audience":"{ iv_audience }","grantType":"urn:ietf:params:oauth:grant-type:token-exchange",| &&
                              |"requestedTokenType":"urn:ietf:params:oauth:token-type:access_token","scope":"https://www.googleapis.com/auth/cloud-platform",| &&
                              |"subjectTokenType":"urn:ietf:params:aws:token-type:aws4_request","subjectToken":"{ iv_subject_token }"\}| ).
    lo_h->send( ). lo_h->receive( ).
    FIND REGEX '"access_token":\s*"([^"]+)"' IN lo_h->response->get_cdata( ) SUBMATCHES rv_token.
    lo_h->close( ).
  ENDMETHOD.

  METHOD get_gcp_access_token.
    DATA: lo_h TYPE REF TO if_http_client.
    cl_http_client=>create_by_url( EXPORTING url = |https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{ p_s_acct }:generateAccessToken| IMPORTING client = lo_h ).
    lo_h->request->set_method( 'POST' ).
    lo_h->request->set_header_field( name = 'Authorization' value = |Bearer { iv_fed_token }| ).
    lo_h->request->set_cdata( '{"scope":["https://www.googleapis.com/auth/bigquery"]}' ).
    lo_h->send( ). lo_h->receive( ).
    FIND REGEX '"accessToken":\s*"([^"]+)"' IN lo_h->response->get_cdata( ) SUBMATCHES rv_token.
    lo_h->close( ).
  ENDMETHOD.

  METHOD hash_sha256.
    DATA: lv_bin TYPE xstring.
    TRY.
        cl_abap_message_digest=>calculate_hash_for_char( 
          EXPORTING 
            if_algorithm   = 'SHA256' 
            if_data        = iv_data 
          IMPORTING 
            ef_hashxstring = lv_bin 
        ).
        rv_hash = to_lower( |{ lv_bin }| ).
      CATCH cx_abap_message_digest.
        CLEAR rv_hash. 
    ENDTRY.
  ENDMETHOD.

  METHOD hmac_sha256.
    TRY.
        cl_abap_hmac=>calculate_hmac_for_char( 
          EXPORTING 
            if_algorithm   = 'SHA256' 
            if_key         = iv_key 
            if_data        = iv_data 
          IMPORTING 
            ef_hmacxstring = rv_hmac 
        ).
      CATCH cx_abap_message_digest.
        CLEAR rv_hmac.
    ENDTRY.
  ENDMETHOD.

  METHOD string_to_xstring.
    cl_abap_conv_out_ce=>create( encoding = 'UTF-8' )->convert( EXPORTING data = iv_str IMPORTING buffer = rv_xstr ).
  ENDMETHOD.

ENDCLASS.

*----------------------------------------------------------------------*
* INITIALIZATION / SCREEN CONTROL
*----------------------------------------------------------------------*
AT SELECTION-SCREEN OUTPUT.
  LOOP AT SCREEN.
    IF screen-group1 = 'WIF' AND rb_test = 'X'.
      screen-active = '0'.
    ELSEIF screen-group1 = 'WIF' AND rb_token = 'X'.
      screen-active = '1'.
    ENDIF.
    MODIFY SCREEN.
  ENDLOOP.

*----------------------------------------------------------------------*
* START OF SELECTION
*----------------------------------------------------------------------*
START-OF-SELECTION.
  DATA(lo_app) = NEW lcl_wif_manager( ).
  IF rb_test = 'X'.
    lo_app->run_test( ).
  ELSE.
    lo_app->run_wif_flow( ).
  ENDIF.

