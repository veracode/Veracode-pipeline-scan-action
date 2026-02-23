#!/usr/bin/env node
import { exec, execSync, spawn } from "child_process";
import * as core from '@actions/core'
import { countReset } from "console";
import { stringify } from "querystring";
import { stdin } from "process";


export function downloadJar ()  {
    core.info('Downloading pipeline-scan.jar')
    try {
        var downloadJar = `curl -sSO https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip`;
        var getDownloadOutput = execSync(downloadJar).toString()
        core.info('pipeline-scan.jar downloaded')
        
    }
    catch(error:any){
        core.warning(`Status Code: ${error.status} with '${error.message}'`);
        
    }
    
    try {
        core.info('Decompressing pipeline-scan-LATEST.zip')
        var unzipJar = 'unzip -o pipeline-scan-LATEST.zip'
        const getUnzipOutput = execSync(unzipJar).toString();
        core.info('pipeline_scan.jar unzipped')
    }
    catch(error:any){
        core.debug(`Status Code: ${error.status} with '${error.message}'`);
        core.warning("Pipeline-scan-LATEST.zip could not be unzipped.")
    }
}

export function runScan (scanCommand:any,parameters:any){

    core.debug('---- DEBUG OUTPUT START ----')
    core.debug('---- pipeline-scan.ts / runScan() ----')
    core.debug('---- Pipeline-scan scan-command: '+scanCommand)
    //core.debug('Get Policy File Command Output: '+commandOutput)
    core.debug('---- DEBUG OUTPUT END ----')


    let commandOutput = ''
    try {
        commandOutput = execSync(scanCommand).toString()
    } catch (ex:any){
        core.debug("Pipeline-scan command failed.\n" + ex.stdout.toString())
        commandOutput = ex.stdout.toString()
    }
    return commandOutput
}

export function getPolicyFile (scanCommand:any,parameters:any){
    let commandOutput = execSync(scanCommand)

    core.debug('---- DEBUG OUTPUT START ----')
    core.debug('---- pipeline-scan.ts / getPolicyFile() ----')
    core.debug('---- Pipeline-scan get Policy File command: '+scanCommand)
    core.debug('---- Get Policy File Command Output: '+commandOutput)
    core.debug('---- DEBUG OUTPUT END ----')

    return commandOutput
  

}