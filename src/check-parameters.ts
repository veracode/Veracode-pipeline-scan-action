import * as core from '@actions/core'
import { runScan, getPolicyFile } from './pipeline-scan'
import * as auth from './auth'
//import { calculateAuthorizationHeader } from './veracode-hmac'

export async function checkParameters (parameters:any):Promise<string>  {

    // Helper function to build Java command with proxy settings
    function buildJavaCommand(baseCommand: string): string {
        const proxyHost = process.env.PROXY_HOST;
        const proxyPort = process.env.PROXY_PORT;
        const proxyUser = process.env.PROXY_USER;
        const proxyPass = process.env.PROXY_PASS;

        if (parameters.debug == 1) {
            core.info('---- DEBUG OUTPUT START ----')
            core.info('---- check-parameters.ts / buildJavaCommand() - proxy settings ----')
            core.info('---- Proxy Host: ' + proxyHost)
            core.info('---- Proxy Port: ' + proxyPort)
            core.info('---- Proxy User: ' + (proxyUser || 'Not set'))
            core.info('---- DEBUG OUTPUT END ----')
        }
        
        if (proxyHost && proxyPort) {
            let proxyArgs = ` -Dhttp.proxyHost=${proxyHost} -Dhttp.proxyPort=${proxyPort}`;
            
            // Add HTTPS proxy settings (same as HTTP for most cases)
            proxyArgs += ` -Dhttps.proxyHost=${proxyHost} -Dhttps.proxyPort=${proxyPort}`;
            
            // Add authentication if provided
            if (proxyUser && proxyPass) {
                proxyArgs += ` -Dhttp.proxyUser=${proxyUser} -Dhttp.proxyPassword=${proxyPass}`;
                proxyArgs += ` -Dhttps.proxyUser=${proxyUser} -Dhttps.proxyPassword=${proxyPass}`;
            }
            
            if (parameters.debug == 1) {
                core.info('---- DEBUG OUTPUT START ----')
                core.info('---- check-parameters.ts / buildJavaCommand() - proxy settings ----')
                core.info('---- Proxy Host: ' + proxyHost)
                core.info('---- Proxy Port: ' + proxyPort)
                core.info('---- Proxy User: ' + (proxyUser || 'Not set'))
                core.info('---- DEBUG OUTPUT END ----')
            }
            
            return baseCommand.replace('java -jar', `java${proxyArgs} -jar`);
        }
        
        return baseCommand;
    }

    if (parameters.debug == 1 ){
        core.info('---- DEBUG OUTPUT START ----')
        core.info('---- check-parameters.ts / checkParameters() ----')
        core.info('---- '+JSON.stringify(parameters))
        core.info('---- DEBUG OUTPUT END ----')
    }

    let scanCommand:string = buildJavaCommand('java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey)
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
            // Check if proxy environment variables are set
            const hasProxy = process.env.http_proxy || process.env.HTTP_PROXY || 
                           process.env.https_proxy || process.env.HTTPS_PROXY;
            
            if (parameters.debug == 1) {
                core.info('---- DEBUG OUTPUT START ----')
                core.info('---- check-parameters.ts / checkParameters() - proxy detection ----')
                core.info('---- Proxy detected: ' + (hasProxy ? 'Yes' : 'No'))
                if (hasProxy) {
                    core.info('---- HTTP_PROXY: ' + (process.env.http_proxy || process.env.HTTP_PROXY || 'Not set'))
                    core.info('---- HTTPS_PROXY: ' + (process.env.https_proxy || process.env.HTTPS_PROXY || 'Not set'))
                }
                core.info('---- DEBUG OUTPUT END ----')
            }
            
            const fetchOptions: any = {
                method: 'GET',
                headers: {
                    'Authorization': auth.generateHeader(path, 'GET', apiUrl, cleanedID, cleanedKEY),
                }
            };
            
            // Only use autoSelectFamily when no proxy is configured
            if (!hasProxy) {
                fetchOptions.autoSelectFamily = true;
                if (parameters.debug == 1) {
                    core.info('---- DEBUG OUTPUT START ----')
                    core.info('---- check-parameters.ts / checkParameters() - using autoSelectFamily ----')
                    core.info('---- autoSelectFamily: true (no proxy detected)')
                    core.info('---- DEBUG OUTPUT END ----')
                }
            } else {
                if (parameters.debug == 1) {
                    core.info('---- DEBUG OUTPUT START ----')
                    core.info('---- check-parameters.ts / checkParameters() - proxy detected, skipping autoSelectFamily ----')
                    core.info('---- autoSelectFamily: false (proxy detected)')
                    core.info('---- DEBUG OUTPUT END ----')
                }
            }
            
            // Add timeout to prevent connection hangs
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
            
            try {
                const response = await fetch('https://'+apiUrl+uriPath+queryparams, {
                    ...fetchOptions,
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                
                if (parameters.debug == 1 ){
                    core.info('---- DEBUG OUTPUT START ----')
                    core.info('---- check-parameters.ts / checkParameters() - fetch response details ----')
                    core.info('---- Response Status: ' + response.status)
                    core.info('---- Response Status Text: ' + response.statusText)
                    core.info('---- Response URL: ' + response.url)
                    core.info('---- Response Headers: ' + JSON.stringify(Object.fromEntries(response.headers.entries())))
                    core.info('---- Response OK: ' + response.ok)
                    core.info('---- Response Type: ' + response.type)
                    core.info('---- DEBUG OUTPUT END ----')
                }
                
                const responseData = await response.json();
                
                if (parameters.debug == 1 ){
                    core.info('---- DEBUG OUTPUT START ----')
                    core.info('---- check-parameters.ts / checkParameters() - find the policy via API----')
                    core.info('---- Response Data ----')
                    core.info(JSON.stringify(responseData))
                    core.info('---- DEBUG OUTPUT END ----')
                }

                if ( responseData.page.total_elements != '0' ){

                    if ( responseData._embedded.policy_versions[0].type == 'BUILTIN' ){
                        core.info('Built-in Policy is required')
                        core.info('Setting policy to '+parameters.veracode_policy_name)
                        scanCommand += ' --policy_name "'+parameters.veracode_policy_name+'"'
                    }
                    else if ( responseData._embedded.policy_versions[0].type == 'CUSTOMER' ){
                        core.info('Custom Policy is required')
                        core.info('Downloading custom policy file and setting policy to '+parameters.veracode_policy_name)


                        policyCommand = buildJavaCommand('java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey+' --request_policy "'+parameters.veracode_policy_name+'"')
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
                else if ( responseData.page.total_elements == undefined ){
                    core.info('Something went wrong with fetching the correct policy')
                }
                else {
                    core.info('NO POLICY FOUND - NO POLICY WILL BE USED TO RATE FINDINGS')
                }
            } catch (err: any) {
                clearTimeout(timeoutId);
                
                if (err.name === 'AbortError') {
                    core.info('Request timed out after 30 seconds');
                    core.info('This might be due to proxy configuration issues');
                } else {
                    core.info('---- DEBUG OUTPUT START ----')
                    core.info('---- check-parameters.ts / checkParameters() - find policy via API catch error ----')
                    core.info('---- Error Type: ' + err.name)
                    core.info('---- Error Message: ' + err.message)
                    if (err.response) {
                        core.info('---- Response Status: ' + err.response.status)
                        core.info('---- Response Data: ' + JSON.stringify(err.response))
                    }
                    core.info('---- DEBUG OUTPUT END ----')
                }
                
                // Continue execution without policy evaluation
                core.info('Continuing without policy evaluation due to API error');
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
        policyCommand = buildJavaCommand('java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey+' --request_policy "'+parameters.request_policy+'"')
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
        if ( key != 'vid' && key != 'vkey' && key != 'run_method' && key != 'request_policy' && key != 'veracode_policy_name' && key != 'artifact_name' && value != "") {
                
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

