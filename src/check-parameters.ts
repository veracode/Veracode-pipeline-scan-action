import * as core from '@actions/core'
import { runScan, getPolicyFile } from './pipeline-scan'
import axios from 'axios'
import * as auth from './auth'
//import { calculateAuthorizationHeader } from './veracode-hmac'

export async function checkParameters (parameters:any):Promise<string>  {

    core.debug('---- DEBUG OUTPUT START ----')
    core.debug('---- check-parameters.ts / checkParameters() ----')
    core.debug('---- '+ JSON.stringify(parameters))
    core.debug('---- DEBUG OUTPUT END ----')

    let scanCommand:string = 'java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey
    let policyCommand:string = ""

    if ( parameters.veracode_policy_name !="" ){
        core.debug('Veracode Policy evaluation is required')
        core.debug('Check the region to select the correct platform')
        if ( parameters.vid.startsWith('vera01ei-') ){
            var apiUrl = 'api.veracode.eu'
            var cleanedID = parameters.vid?.replace('vera01ei-','') ?? '';
            var cleanedKEY = parameters.vkey?.replace('vera01es-','') ?? '';
            core.debug('Region: EU')
        }
        else {
            var apiUrl = 'api.veracode.com'
            var cleanedID = parameters.vid
            var cleanedKEY = parameters.vkey
            core.debug('Region: US')
        }
        core.debug('Check whether a built-in or a custom policy is required')

        
        const uriPath = '/appsec/v1/policies'
        const queryparams = '?name='+encodeURIComponent(parameters.veracode_policy_name)
        const path = uriPath+queryparams
        const appUrl = apiUrl+uriPath+queryparams
        //const headers = {'Authorization':auth.generateHeader(appUrl, 'GET', apiUrl, cleanedID, cleanedKEY)}

        core.debug('---- DEBUG OUTPUT START ----')
        core.debug('---- check-parameters.ts / checkParameters() - if veracode_policy_name is set - show parameters ----')
        core.debug('---- Response Data ----')
        core.debug('---- URI Path: '+uriPath)
        core.debug('---- Query Params: '+queryparams)
        core.debug('---- Path: '+path)
        core.debug('---- App Url: '+appUrl)
        core.debug('---- DEBUG OUTPUT END ----')


//        try {
            const response = await axios.request({
                method: 'GET',
                headers: {
                    'Authorization': auth.generateHeader(path, 'GET', apiUrl, cleanedID, cleanedKEY),
                },
                url: 'https://'+apiUrl+uriPath+queryparams
            });

            core.debug('---- DEBUG OUTPUT START ----')
            core.debug('---- check-parameters.ts / checkParameters() - find the policy via API----')
            core.debug('---- Response Data ----')
            core.debug(JSON.stringify(response.data))
            core.debug('---- DEBUG OUTPUT END ----')

            if ( response.data.page.total_elements != '0' ){

                if ( response.data._embedded.policy_versions[0].type == 'BUILTIN' ){
                    core.debug('Built-in Policy is required')
                    core.debug('Setting policy to '+parameters.veracode_policy_name)
                    scanCommand += ' --policy_name "'+parameters.veracode_policy_name+'"'
                }
                else if ( response.data._embedded.policy_versions[0].type == 'CUSTOMER' ){
                    core.debug('Custom Policy is required')
                    core.debug('Downloading custom policy file and setting policy to '+parameters.veracode_policy_name)


                    policyCommand = 'java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey+' --request_policy "'+parameters.veracode_policy_name+'"'
                    const policyDownloadOutput = await getPolicyFile(policyCommand,parameters)

                    core.debug('---- DEBUG OUTPUT START ----')
                    core.debug('---- check-parameters.ts / checkParameters() - if veracode_policy_name is set and custom policy is required ----')
                    core.debug('---- Policy Download command: '+policyCommand)
                    core.debug('---- Policy Downlaod Output: '+policyDownloadOutput)
                    core.debug('---- DEBUG OUTPUT END ----')

                    var policyFileName = parameters.veracode_policy_name.replace(/ /gi, "_")
                    core.debug('Policy Filen Name: '+policyFileName)
                    scanCommand += " --policy_file "+policyFileName+".json"
                }
            }
            else if ( response.data.page.total_elements == undefined ){
                core.debug('Something went wrong with fetching the correct policy')
            }
            else {
                core.debug('NO POLICY FOUND - NO POLICY WILL BE USED TO RATE FINDINGS')
            }
/*
        } catch (err: any) {
            core.debug('---- DEBUG OUTPUT START ----')
            core.debug('---- check-parameters.ts / checkParameters() - find policy via API catch error ----')
            core.debug('---- Response Data ----')
            core.debug(err.response)
            core.debug('---- DEBUG OUTPUT END ----')
            console.error(err.response);
        }
*/
        


    }
    

    //this will go away in thex version of the action, function is deprecated - start
    if ( parameters.request_policy != ""){
        core.debug('Policy file download required')
        policyCommand = 'java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey+' --request_policy "'+parameters.request_policy+'"'
        const policyDownloadOutput = await getPolicyFile(policyCommand,parameters)

        core.debug('---- DEBUG OUTPUT START ----')
        core.debug('---- check-parameters.ts / checkParameters() - if request policy == true ----')
        core.debug('---- Policy Download command: '+policyCommand)
        core.debug('---- Policy Downlaod Output: '+policyDownloadOutput)
        core.debug('---- DEBUG OUTPUT END ----')

            
        var policyFileName = parameters.request_policy.replace(/ /gi, "_")
        core.debug('Policy Filen Name: '+policyFileName)
        scanCommand += " --policy_file "+policyFileName+".json"
    }
    //this will go away in thex version of the action, function is deprecated - end
        
    core.debug('create pipeline-scan scan command')
    Object.entries(parameters).forEach(([key, value], index) => {
        if ( key != 'vid' && key != 'vkey' && key != 'run_method' && key != 'request_policy' && key != 'veracode_policy_name' && key != 'artifact_name' && value != "") {
                
            core.debug('---- DEBUG OUTPUT START ----')
            core.debug('---- check-parameters.ts / checkParameters() - run full scan----')
            core.debug('---- Parameter: '+key+' value: '+value)
            core.debug('---- DEBUG OUTPUT END ----')

            if ( key != "debug" && key != "store_baseline_file" && key != "store_baseline_file_branch" && key != "create_baseline_from" && key != "fail_build" ) {
                if ( key == "include" ){
                    scanCommand += " --"+key+" '"+value+"'"
                }
                else {
                scanCommand += " --"+key+" "+value
                }
            }

            core.debug('---- DEBUG OUTPUT START ----')
            core.debug('---- check-parameters.ts / checkParameters() - run full scan----')
            core.debug('---- Pipeline Scan Command: '+scanCommand)
            core.debug('---- DEBUG OUTPUT END ----')
        }
    });

    core.debug('---- DEBUG OUTPUT START ----')
    core.debug('---- check-parameters.ts / checkParameters() - return value ----')
    core.debug('---- Pipeline Scan Command: '+scanCommand)
    core.debug('---- DEBUG OUTPUT END ----')

    return scanCommand
}

