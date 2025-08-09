// Chanaka updated for speke v2 - 2024/10/24 - CENC + PR Added
const { decryptSecret } = require('utils.js');
const https = require('https');
const xml2js = require('xml2js'); 
const xmlbuilder = require('xmlbuilder');
const crypto = require('crypto');

const WIDEVINE_SYSTEM_ID = 'edef8ba9-79d6-4ace-a3c8-27dcd51d21ed';
const PLAYREADY_SYSTEM_ID = '9a04f079-9840-4286-ab92-e65be0885f95';
const FAIRPLAY_SYSTEM_ID = '94ce86fb-07ff-4f43-adb8-93d2fa968ca2';

const HLSSIGNALLINGDATA_TAG_MASTER = '#EXT-X-SESSION-KEY';
const HLSSIGNALLINGDATA_TAG_MEDIA = '#EXT-X-KEY'; 


const post = (data,k_user,k_pass) => new Promise((resolve, reject) => {
    console.log('start post');
    console.log('payload: '+ data);

    var options = {
        host: process.env.KMS_HOST, 
        port: process.env.KMS_PORT,
        method: 'POST',
        path: process.env.KMS_PATH,
        headers: {
            'Content-Type': 'application/xml',
            'Content-Length': data.length,
            'Authorization': 'Basic ' + Buffer.from(k_user + ':' + k_pass).toString('base64')
        }   
    };

    console.log(options);
    const req = https.request(options, res => {
        let buffer = "";
        console.log(`statusCode: ${res.statusCode}`);
        console.log(JSON.stringify(res.headers));
        res.on('data', chunk => buffer += chunk);
        res.on('end', () => resolve(buffer));
    });
    req.on('error', e => reject(e.message));
    req.end(data);
});

exports.handler =  async (event, context, callback) => {

    console.log('.....start handler');

    const kms_user = await decryptSecret('UDRM_USER');
    const kms_pass = await decryptSecret('UDRM_PASS');    

    var options = { 
        explicitCharkey: false,
        trim: false,
        normalize: false,
        explicitRoot: true,
        emptyTag: null,
        explicitArray: true,
        ignoreAttrs: false,
        mergeAttrs: false,
        validator: null
      };

    var parser = new xml2js.Parser(options);
 
    var xml = event.body;
    
    console.log("xml:..."+xml);
    
    if (event.isBase64Encoded === true) {
        xml = Buffer.from(xml, 'base64').toString('utf-8');
        
    }
    
    console.log("event:..."+  JSON.stringify(event));

    var xml_response = await post(xml,kms_user,kms_pass);

    console.log("udrm response:..."+ xml_response);

    // Let's turn the XML into a Javascript object
    parser.parseString(xml_response, function (err, json) {

        // If something went wrong, the callback first argument contains the error object that will be sent to API gateway
        if (err!=null) {
           console.log("err");
           callback(err, null);
        } else {

            console.log("udrm response in json:..." + JSON.stringify(json));
            
            if (event.headers['x-speke-version'] && event.headers['x-speke-version'] == '2.0') {
                    console.log("SPEKEv2...Start manipulations")
                    json['cpix:CPIX']['$']['xmlns:pskc']='urn:ietf:params:xml:ns:keyprov:pskc';
                    console.log(json);


                    // go over all DRMSystermList items
                    for (const dsl in json['cpix:CPIX']['cpix:DRMSystemList']) {
                        const drmList = json['cpix:CPIX']['cpix:DRMSystemList'][dsl]; 
                        //    go over each DRMSystem    
                        for (const ds in drmList['cpix:DRMSystem']) {
                            const drmSystem =drmList['cpix:DRMSystem'][ds];
                            var drmSystemUpd = drmSystem;
                            const kid = drmSystem['$']['kid'];
                            const systemId = drmSystem['$']['systemId']; 
                            const pssh = drmSystem['cpix:PSSH'];
                            const uppercase = String(kid).toUpperCase();
                            const keyid1 = uppercase.replace(/-/g,'');

                            var raw_master_hls;
                            var raw_media_hls;
                            var b64_master_hls;
                            var b64_media_hls;
                            
                            var raw_master;
                            var raw_media;
                            var b64_master;
                            var b64_media;

                            switch (systemId) {
                                case FAIRPLAY_SYSTEM_ID:
                                    console.log('SPEKEv2 Adapt FPS');
                                    // create HLSSignallingData for FPS
                                    raw_master_hls = HLSSIGNALLINGDATA_TAG_MASTER + ':METHOD=SAMPLE-AES,URI="skd://' + kid + '",KEYFORMAT="com.apple.streamingkeydelivery",KEYFORMATVERSIONS="1"'; 
                                    raw_media_hls = HLSSIGNALLINGDATA_TAG_MEDIA + ':METHOD=SAMPLE-AES,URI="skd://' + kid + '",KEYFORMAT="com.apple.streamingkeydelivery",KEYFORMATVERSIONS="1"';
                                    b64_master_hls = Buffer.from(raw_master_hls).toString('base64');
                                    b64_media_hls = Buffer.from(raw_media_hls).toString('base64');

                                    console.log('raw_master_hls, hlssignallingdata...'+ raw_master_hls )
                                    console.log('hlssignallingdata.master_hls..'+ b64_master_hls );
                                    console.log('raw_master_hls, hlssignallingdata...'+ raw_media_hls );
                                    console.log('hlssignallingdata.media_hls..'+ b64_media_hls );   

                                    if (drmSystem['cpix:HLSSignalingData'][0]) {
                                        if (drmSystem['cpix:HLSSignalingData'][0]['$']['playlist'] == 'master') {
                                            drmSystemUpd['cpix:HLSSignalingData'][0]['_'] = b64_master_hls;
                                        } else {
                                            drmSystemUpd['cpix:HLSSignalingData'][0]['_'] = b64_media_hls;
                                        }
                                    }

                                    if (drmSystem['cpix:HLSSignalingData'][1]) {
                                        if (drmSystem['cpix:HLSSignalingData'][1]['$']['playlist'] == 'master') {
                                            drmSystemUpd['cpix:HLSSignalingData'][1]['_'] = b64_master_hls;
                                        } else {
                                            drmSystemUpd['cpix:HLSSignalingData'][1]['_'] = b64_media_hls;
                                        }
                                    }

                                    // remove speke ns elements
                                    if (drmSystemUpd['cpix:URIExtXKey']) {
                                        delete drmSystemUpd['cpix:URIExtXKey']
                                    }
                                    if (drmSystemUpd['speke:KeyFormat']) {
                                        delete drmSystemUpd['speke:KeyFormat'];
                                    }
                                    if (drmSystemUpd['speke:KeyFormatVersions']) {
                                        delete drmSystemUpd['speke:KeyFormatVersions'];
                                    }

                                    break;

                                case WIDEVINE_SYSTEM_ID:
                                    console.log('SPEKEv2 Adapt WV');
                                    // create contentProtectionData
                                    // check if pssh is there, if not error. 
                                    if (drmSystem['cpix:PSSH']) {
                                        let pssh = drmSystem['cpix:PSSH']; 
                                        let contentProtectionData = `<pssh xmlns="urn:mpeg:cenc:2013">${pssh}</pssh>`;
                                        drmSystemUpd['cpix:ContentProtectionData'] = Buffer.from(contentProtectionData).toString('base64'); 
                                    }
                                    else {
                                        console.log('PSSH MISSING in the response');
                                    }
                                    

                                    // create HLSSignallingData
                                    raw_master = HLSSIGNALLINGDATA_TAG_MASTER + ':METHOD=SAMPLE-AES-CTR,URI="data:text/plain;base64,'  + pssh + '",KEYID=0x' + keyid1 + ',KEYFORMAT="urn:uuid:' + systemId + '",KEYFORMATVERSIONS="1"'; 
                                    raw_media = HLSSIGNALLINGDATA_TAG_MEDIA + ':METHOD=SAMPLE-AES-CTR,URI="data:text/plain;base64,'  + pssh + '",KEYID=0x' + keyid1 + ',KEYFORMAT="urn:uuid:' + systemId + '",KEYFORMATVERSIONS="1"'; 
                                    b64_master = Buffer.from(raw_master).toString('base64');
                                    b64_media = Buffer.from(raw_media).toString('base64');

                                    console.log('hlssignallingdata.master..'+ b64_master );
                                    console.log('raw_master_hlssignallingdata...'+ raw_media );
                                    console.log('hlssignallingdata.media..'+ b64_media );
                                    console.log('raw_master_hlssignallingdata...'+ raw_master );
                                    
                                    if (drmSystem['cpix:HLSSignalingData'][0]) {
                                        if (drmSystem['cpix:HLSSignalingData'][0]['$']['playlist'] == 'master') {
                                            drmSystemUpd['cpix:HLSSignalingData'][0]['_'] = b64_master;
                                        } else {
                                            drmSystemUpd['cpix:HLSSignalingData'][0]['_'] = b64_media;
                                        }
                                    }

                                    if (drmSystem['cpix:HLSSignalingData'][1]) {
                                        if (drmSystem['cpix:HLSSignalingData'][1]['$']['playlist'] == 'master') {
                                            drmSystemUpd['cpix:HLSSignalingData'][1]['_'] = b64_master;
                                        } else {
                                            drmSystemUpd['cpix:HLSSignalingData'][1]['_'] = b64_media;
                                        }
                                    }

                                    break;

                                case PLAYREADY_SYSTEM_ID:
                                    console.log('SPEKEv2 Adapt PR');
                                    
                                    // set ContentProtectionHeader
                                    const create_mss_data = 1;                               
                                    if (drmSystem['cpix:PSSH'] && create_mss_data === 1) {
                                        console.log(`INFO pssh...` + pssh);

                                        const pssh_str = atob(pssh);
                                        const pssh_buf = new ArrayBuffer(pssh_str.length);
                                    
                                        console.log('DEBUG pssh_buf...');
                                        console.log(pssh_buf);
                                    
                                        const bufView = new Uint8Array(pssh_buf);
                                      
                                        console.log('DEBUG bufView...');
                                        console.log(bufView);
                                    
                                        pssh_str
                                          .split("")
                                          .map(char => char.charCodeAt(0))
                                          .forEach((code, idx) => (bufView[idx] = code));

                                        console.log('DEBUG pssh_buf...');
                                        console.log(pssh_buf);      
                                        
                                        var offset = 0;
                                        offset += 12; // skip version and systemId

                                        const mspro_buf = pssh_buf.slice(offset);
                                        const mspro = Buffer.from(mspro_buf).toString('base64');
                                        console.log(`INFO mspro...` + mspro);

                                        const contentProtectionDataRaw = `<pssh xmlns="urn:mpeg:cenc:2013">${pssh}</pssh><pro xmlns="urn:microsoft:playready">${mspro}</pro>`;
                                        const contentProtectionData = Buffer.from(contentProtectionDataRaw).toString('base64');

                                        console.log(`DEBUG contentProtectionDataRaw...` + contentProtectionDataRaw);
                                        console.log(`INFO contentProtectionData...` + contentProtectionData);

                                        drmSystemUpd['cpix:ContentProtectionData'] = contentProtectionData;
                                        drmSystemUpd['cpix:SmoothStreamingProtectionHeaderData'] = mspro;

                                        if (drmSystem['speke:ProtectionHeader']) {
                                            delete drmSystemUpd['speke:ProtectionHeader']; 
                                        }

                                    }

                                    // create HLSSignallingData
                                    raw_master = HLSSIGNALLINGDATA_TAG_MASTER + ':METHOD=SAMPLE-AES-CTR,URI="data:text/plain;base64,'  + pssh + '",KEYID=0x' + keyid1 + ',KEYFORMAT="urn:uuid:' + systemId + '",KEYFORMATVERSIONS="1"'; 
                                    raw_media = HLSSIGNALLINGDATA_TAG_MEDIA + ':METHOD=SAMPLE-AES-CTR,URI="data:text/plain;base64,'  + pssh + '",KEYID=0x' + keyid1 + ',KEYFORMAT="urn:uuid:' + systemId + '",KEYFORMATVERSIONS="1"'; 
                                    b64_master = Buffer.from(raw_master).toString('base64');
                                    b64_media = Buffer.from(raw_media).toString('base64');

                                    console.log('hlssignallingdata.master..'+ b64_master );
                                    console.log('raw_master_hlssignallingdata...'+ raw_media );
                                    console.log('hlssignallingdata.media..'+ b64_media );
                                    console.log('raw_master_hlssignallingdata...'+ raw_master );
                                    
                                    if (drmSystem['cpix:HLSSignalingData'][0]) {
                                        if (drmSystem['cpix:HLSSignalingData'][0]['$']['playlist'] == 'master') {
                                            drmSystemUpd['cpix:HLSSignalingData'][0]['_'] = b64_master;
                                        } else {
                                            drmSystemUpd['cpix:HLSSignalingData'][0]['_'] = b64_media;
                                        }
                                    }

                                    if (drmSystem['cpix:HLSSignalingData'][1]) {
                                        if (drmSystem['cpix:HLSSignalingData'][1]['$']['playlist'] == 'master') {
                                            drmSystemUpd['cpix:HLSSignalingData'][1]['_'] = b64_master;
                                        } else {
                                            drmSystemUpd['cpix:HLSSignalingData'][1]['_'] = b64_media;
                                        }
                                    }


                                    break;

                                default:
                                    console.log('INVALID systemID:' + systemId);
                                    break;
                            }

                            json['cpix:CPIX']['cpix:DRMSystemList'][dsl]['cpix:DRMSystem'][ds] = drmSystemUpd;
                            console.log("dsl="+dsl+",ds="+ds);
                            console.log(drmSystemUpd);
                            console.log(json);
                        }
                    }

                    var builder = new xml2js.Builder({headless: true});
                    xml_response = builder.buildObject(json);
                    console.log('xml_response after manipulation...'+xml_response); 
            }


            var headers = {
                'X-Speke-Version': '2.0',
                'X-Speke-User-Agent': 'SPEKE Lambda BE 1',
                'Content-Type': 'application/xml'
            };
          
            var isBase64EncodedRet = event.isBase64Encoded ? event.isBase64Encoded : false;
            
            var bodyRet = event.isBase64Encoded ? Buffer.from(xml_response).toString('base64') : xml_response;
          
            // Now prepare the response object
            var resp = {
                // Return this as a successful "200" response
                // isBase64Encoded: true,
                isBase64Encoded: isBase64EncodedRet,
                statusCode: 200,
                headers: headers,
                // body: Buffer.from(xml_response).toString('base64')
                body: bodyRet
            }
          
            console.log(JSON.stringify(resp));
          
            // Now, call the callback with the response above
            callback(null, resp)
            
        }
    });

};