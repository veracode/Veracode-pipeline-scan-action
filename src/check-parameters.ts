import * as core from '@actions/core'
import { runScan, getPolicyFile } from './pipeline-scan'
import axios from 'axios'
import * as auth from './auth'
//import { calculateAuthorizationHeader } from './veracode-hmac'

export async function checkParameters (parameters:any):Promise<string>  {


    if (parameters.debug == 1 ){
        core.info('---- DEBUG OUTPUT START ----')
        core.info('---- check-parameters.ts / checkParameters() ----')
        core.info('---- '+JSON.stringify(parameters))
        core.info('---- DEBUG OUTPUT END ----')
    }

    let scanCommand:string = 'java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey+' -jf results.json -fjf filtered_results.json'
    let policyCommand:string = ""

    if ( parameters.veracode_policy_name !="" ){
        core.info('Veracode Policy evaluation is required')
        core.info('Check the region to select the correct platform')
        if ( parameters.vid.startsWith('vera01ei-') ){
            var apiUrl = 'api.veracode.eu'
            var cleanedID = parameters.vid?.replace('vera01ei-','') ?? '';
            var cleanedKEY = parameters.vkey?.replace('vera01es-','') ?? '';
            core.info('Region: EU')
        }
        else {
            var apiUrl = 'api.veracode.com'
            var cleanedID = parameters.vid
            var cleanedKEY = parameters.vkey
            core.info('Region: US')
        }
        core.info('Check whether a built-in or a custom policy is required')

        
        const uriPath = '/appsec/v1/policies'
        const queryparams = '?name='+encodeURIComponent(parameters.veracode_policy_name)
        const path = uriPath+queryparams
        const appUrl = apiUrl+uriPath+queryparams
        //const headers = {'Authorization':auth.generateHeader(appUrl, 'GET', apiUrl, cleanedID, cleanedKEY)}

        core.info('---- DEBUG OUTPUT START ----')
        core.info('---- check-parameters.ts / checkParameters() - if veracode_policy_name is set - show parameters ----')
        core.info('---- Response Data ----')
        core.info('---- URI Path: '+uriPath)
        core.info('---- Query Params: '+queryparams)
        core.info('---- Path: '+path)
        core.info('---- App Url: '+appUrl)
        core.info('---- DEBUG OUTPUT END ----')


//        try {
            const response = await axios.request({
                method: 'GET',
                headers: {
                    'Authorization': auth.generateHeader(path, 'GET', apiUrl, cleanedID, cleanedKEY),
                },
                url: 'https://'+apiUrl+uriPath+queryparams
            });
            if (parameters.debug == 1 ){
                core.info('---- DEBUG OUTPUT START ----')
                core.info('---- check-parameters.ts / checkParameters() - find the policy via API----')
                core.info('---- Response Data ----')
                core.info(JSON.stringify(response.data))
                core.info('---- DEBUG OUTPUT END ----')
            }

            if ( response.data.page.total_elements != '0' ){

                if ( response.data._embedded.policy_versions[0].type == 'BUILTIN' ){
                    core.info('Built-in Policy is required')
                    core.info('Setting policy to '+parameters.veracode_policy_name)
                    scanCommand += ' --policy_name "'+parameters.veracode_policy_name+'"'
                }
                else if ( response.data._embedded.policy_versions[0].type == 'CUSTOMER' ){
                    core.info('Custom Policy is required')
                    core.info('Downloading custom policy file and setting pilicy to '+parameters.veracode_policy_name)


                    policyCommand = 'java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey+' --request_policy "'+parameters.veracode_policy_name+'"'
                    const policyDownloadOutput = await getPolicyFile(policyCommand,parameters)

                    if (parameters.debug == 1 ){
                        core.info('---- DEBUG OUTPUT START ----')
                        core.info('---- check-parameters.ts / checkParameters() - if veracode_policy_name is set and custom policy is required ----')
                        core.info('---- Policy Download command: '+policyCommand)
                        core.info('---- Policy Downlaod Output: '+policyDownloadOutput)
                        core.info('---- DEBUG OUTPUT END ----')
                    }

                    var policyFileName = parameters.veracode_policy_name.replace(/ /gi, "_")
                    core.info('Policy Filen Name: '+policyFileName)
                    scanCommand += " --policy_file "+policyFileName+".json"
                }
            }
            else if ( response.data.page.total_elements == undefined ){
                core.info('Something went wrong with fetching the correct policy')
            }
            else {
                core.info('NO POLICY FOUND - NO POLICY WILL BE USED TO RATE FINDINGS')
            }
/*
        } catch (err: any) {
            core.info('---- DEBUG OUTPUT START ----')
            core.info('---- check-parameters.ts / checkParameters() - find policy via API catch error ----')
            core.info('---- Response Data ----')
            core.info(err.response)
            core.info('---- DEBUG OUTPUT END ----')
            console.error(err.response);
        }
*/
        


    }
    

    //this will go away in thex version of the action, function is deprecated - start
    if ( parameters.request_policy != ""){
        core.info('Policy file download required')
        policyCommand = 'java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey+' --request_policy "'+parameters.request_policy+'"'
        const policyDownloadOutput = await getPolicyFile(policyCommand,parameters)

        if (parameters.debug == 1 ){
            core.info('---- DEBUG OUTPUT START ----')
            core.info('---- check-parameters.ts / checkParameters() - if request policy == true ----')
            core.info('---- Policy Download command: '+policyCommand)
            core.info('---- Policy Downlaod Output: '+policyDownloadOutput)
            core.info('---- DEBUG OUTPUT END ----')
        }

            
        var policyFileName = parameters.request_policy.replace(/ /gi, "_")
        core.info('Policy Filen Name: '+policyFileName)
        scanCommand += " --policy_file "+policyFileName+".json"
    }
    //this will go away in thex version of the action, function is deprecated - end
        
    core.info('create pipeline-scan scan command')
    Object.entries(parameters).forEach(([key, value], index) => {
        if ( key != 'vid' && key != 'vkey' && key != 'run_method' && key != 'request_policy' && key != 'veracode_policy_name' && value != "") {
                
            if (parameters.debug == 1 ){
                core.info('---- DEBUG OUTPUT START ----')
                core.info('---- check-parameters.ts / checkParameters() - run full scan----')
                core.info('---- Parameter: '+key+' value: '+value)
                 core.info('---- DEBUG OUTPUT END ----')
            }
            if ( key != "debug" && key != "store_baseline_file" && key != "store_baseline_file_branch" && key != "create_baseline_from" && key != "fail_build" ) {
                if ( key == "include" ){
                    scanCommand += " --"+key+" '"+value+"'"
                }
                else {
                scanCommand += " --"+key+" "+value
                }
            }

            if (parameters.debug == 1 ){
                core.info('---- DEBUG OUTPUT START ----')
                core.info('---- check-parameters.ts / checkParameters() - run full scan----')
                core.info('---- Pipeline Scan Command: '+scanCommand)
                core.info('---- DEBUG OUTPUT END ----')
            }
        }
    });



    if (parameters.debug == 1 ){
        core.info('---- DEBUG OUTPUT START ----')
        core.info('---- check-parameters.ts / checkParameters() - return value ----')
        core.info('---- Pipeline Scan Command: '+scanCommand)
        core.info('---- DEBUG OUTPUT END ----')
    }

    return scanCommand
}

