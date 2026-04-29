#!/usr/bin/env node
import { exec, execSync, spawn } from "child_process";
import * as core from '@actions/core'
import axios from 'axios'
import * as auth from './auth'


export function downloadJar ()  {
    core.info('Downloading pipeline-scan.jar')
    try {
        var downloadJar = `curl -sSO https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip`;
        var getDownloadOutput = execSync(downloadJar).toString()
        core.info('pipeline-scan.jar downloaded')
        
    }
    catch(error:any){
        core.info(`Status Code: ${error.status} with '${error.message}'`);
        
    }
    
    try {
        var unzipJar = 'unzip -o pipeline-scan-LATEST.zip'
        const getUnzipOutput = execSync(unzipJar).toString();
        core.info('pipeline_scan.jar unzipped')
    }
    catch(error:any){
        console.log(`Status Code: ${error.status} with '${error.message}'`);
        core.info("Pipeline-scan-LATEST.zip could not be unzipped.")
    }
}

export function runScan (scanCommand:any,parameters:any){
    

    if (parameters.debug == 1 ){
        core.info('---- DEBUG OUTPUT START ----')
        core.info('---- pipeline-scan.ts / runScan() ----')
        core.info('---- Pipeline-scan scan-command: '+scanCommand)
        //core.info('Get Policy File Command Output: '+commandOutput)
        core.info('---- DEBUG OUTPUT END ----')
    }


    let commandOutput = ''
    try {
        commandOutput = execSync(scanCommand).toString()
    } catch (ex:any){
        core.info("Pipeline-scan command failed.\n"+ex.stdout.toString())
        commandOutput = ex.stdout.toString()
    }
    return commandOutput
}

export function getPolicyFile (scanCommand:any,parameters:any){
    let commandOutput = execSync(scanCommand)

    if (parameters.debug == 1 ){
        core.info('---- DEBUG OUTPUT START ----')
        core.info('---- pipeline-scan.ts / getPolicyFile() ----')
        core.info('---- Pipeline-scan get Policy File command: '+scanCommand)
        core.info('---- Get Policy File Command Output: '+commandOutput)
        core.info('---- DEBUG OUTPUT END ----')
    }

    return commandOutput
  

}

export async function getPolicyNameByProfileName(inputs: any) {
    const appname = inputs.app_name;
    const vid = inputs.vid;
    const vkey = inputs.vkey;
    let policyName = ''
    try {
      const application = await getApplicationByName(appname, vid, vkey);
      policyName = application.profile.policies[0].name
    } catch (error) {
      core.info(`No application found with name ${appname}`);
      policyName = inputs.veracode_policy_name
    }
    core.info(`Setting the Policy to ${policyName}`)
    return policyName
  }

export async function getApplicationByName(
    appname: string,
    vid: string,
    vkey: string,
  ) {
    try {
        if ( vid.startsWith('vera01ei-') ){
            var apiUrl = 'api.veracode.eu'
            var cleanedID = vid?.replace('vera01ei-','') ?? '';
            var cleanedKEY = vkey?.replace('vera01es-','') ?? '';
            core.info('Region: EU')
        }
        else {
            var apiUrl = 'api.veracode.com'
            var cleanedID = vid
            var cleanedKEY = vkey
            core.info('Region: US')
        }
        const resourceUri = `/appsec/v1/applications`
        const queryparams = '?name='+encodeURIComponent(appname)
        const path = resourceUri+queryparams
        const appUrl = apiUrl+resourceUri+queryparams

        const response = await axios.request({
            method: 'GET',
            headers: {
                'Authorization': auth.generateHeader(path, 'GET', apiUrl, cleanedID, cleanedKEY),
            },
            url: 'https://'+appUrl
        });
      const applications:any[] = response.data._embedded?.applications || [];
      if (applications.length === 0) { // no application with the given name was found
        core.warning(`No application found with name ${appname}`);
        core.info("Setting the Policy to User Defined Policy")
        return []
      } 

      const filteredApplications = applications.filter(app => app.profile?.name === appname);
      if (filteredApplications.length === 0) { // no application with the exact given name was found
        core.warning(`No application found with exact name ${JSON.stringify(appname)}. Returning the first application from the list in the original API query.`);
        return applications[0];
      } else if (filteredApplications.length > 1) {
        core.warning(`Multiple applications (${filteredApplications.length}) found with exact name ${JSON.stringify(appname)}. Returning the first application from the filtered list.`);  
      } else { // exactly one application with the exact given name was found
        if (applications.length > 1) {
          core.info(`One application found with exact name ${JSON.stringify(appname)}. While there were ${JSON.stringify(applications.length)} applications starting with ${JSON.stringify(appname)}.`);
        } else {
          core.info(`One application found with exact name ${JSON.stringify(appname)}.`);
        }
      }
      return filteredApplications[0];

    } catch (error) {
      throw error;
    }
  }