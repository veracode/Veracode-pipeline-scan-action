import * as core from '@actions/core'
import { runScan, getPolicyFile } from './pipeline-scan'


export async function checkParameters (parameters:any):Promise<string>  {


    if (parameters.debug == 1 ){
        core.info('---- DEBUG OUTPUT START ----')
        core.info('---- check-parameters.ts / checkParameters() ----')
        core.info('---- '+JSON.stringify(parameters))
        core.info('---- DEBUG OUTPUT END ----')
    }

    let scanCommand:string = 'java -jar pipeline-scan.jar -vid '+parameters.vid+' -vkey '+parameters.vkey+' -jf results.json -fjf filtered_results.json'
    let policyCommand:string = ""
       
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
        
    core.info('create pipeline-scan scan command')
    Object.entries(parameters).forEach(([key, value], index) => {
        if ( key != 'vid' && key != 'vkey' && key != 'run_method' && key != 'request_policy' && value != "") {
                
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

