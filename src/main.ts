import { readFileSync, existsSync, fstat, writeFileSync} from 'fs';
import * as github from '@actions/github'
import * as core from '@actions/core'
import { DefaultArtifactClient } from '@actions/artifact';
import * as artifactV1 from '@actions/artifact-v1';
import { downloadJar } from "./pipeline-scan";
import { runScan } from "./pipeline-scan";
import { checkParameters } from './check-parameters';
import { commitBasline } from './commit';
import { json } from 'stream/consumers';
import { stringify } from 'querystring';
import { env } from "process";
import { GitHub } from '@actions/github/lib/utils';


function getInputParameters(){
    // get input params
    let parameters:any = {}

    const vid = core.getInput('vid', {required: true} );
    parameters['vid'] = vid

    const vkey = core.getInput('vkey', {required: true} );
    parameters['vkey'] = vkey

    const file = core.getInput('file', {required: true} );
    parameters['file'] = file

    /*
    const run_method = core.getInput('run_method', {required: true} );
    parameters['run_method'] = run_method
    */

    const veracode_policy_name = core.getInput('veracode_policy_name', {required: false});
    parameters['veracode_policy_name'] = veracode_policy_name

    const request_policy = core.getInput('request_policy', {required: false} );
    parameters['request_policy'] = request_policy

    const fail_on_severity = core.getInput('fail_on_severity', {required: false} );
    parameters['fail_on_severity'] = fail_on_severity

    const fail_on_cwe = core.getInput('fail_on_cwe', {required: false} );
    parameters['fail_on_cwe'] = fail_on_cwe

    const baseline_file = core.getInput('baseline_file', {required: false} );
    parameters['baseline_file'] = baseline_file

    const policy_name = core.getInput('policy_name', {required: false} );
    parameters['policy_name'] = policy_name

    const policy_file = core.getInput('policy_file', {required: false} );
    parameters['policy_file'] = policy_file

    const timeout = core.getInput('timeout', {required: false} );
    parameters['timeout'] = timeout

    const issue_details = core.getInput('issue_details', {required: false} );
    parameters['issue_details'] = issue_details

    const summary_display = core.getInput('summary_display', {required: false} );
    parameters['summary_display'] = summary_display

    const json_display = core.getInput('json_display', {required: false} );
    parameters['json_display'] = json_display

    const verbose = core.getInput('verbose', {required: false} );
    parameters['verbose'] = verbose

    const summary_output = core.getInput('summary_output', {required: false} );
    parameters['summary_output'] = summary_output

    const summary_output_file = core.getInput('summary_output_file', {required: false} );
    parameters['summary_output_file'] = summary_output_file

    const json_output = core.getInput('json_output', {required: false} );
    parameters['json_output'] = json_output

    const include = core.getInput('include', {required: false} );
    parameters['include'] = include

    const json_output_file = core.getInput('json_output_file', {required: false} );
    parameters['json_output_file'] = json_output_file

    const filtered_json_output_file = core.getInput('filtered_json_output_file', {required: false} );
    parameters['filtered_json_output_file'] = filtered_json_output_file

    const project_name = core.getInput('project_name', {required: false} );
    parameters['project_name'] = project_name

    const project_url = core.getInput('project_url', {required: false} );
    parameters['project_url'] = project_url

    const project_ref = core.getInput('project_ref', {required: false} );
    parameters['project_ref'] = project_ref

    const app_id = core.getInput('app_id', {required: false} );
    parameters['app_id'] = app_id

    const development_stage = core.getInput('development_stage', {required: false} );
    parameters['development_stage'] = development_stage

    // const debug = core.getInput('debug', {required: false} );
    // parameters['debug'] = debug

    const store_baseline_file = core.getInput('store_baseline_file', {required: false} );
    parameters['store_baseline_file'] = store_baseline_file
    //true or false

    const store_baseline_file_branch = core.getInput('store_baseline_file_branch', {required: false} );
    parameters['store_baseline_file_branch'] = store_baseline_file_branch

    const create_baseline_from = core.getInput('create_baseline_from', {required: false} );
    parameters['create_baseline_from'] = create_baseline_from
    //standard or filtered 

    const fail_build = core.getInput('fail_build', {required: false} );
    parameters['fail_build'] = fail_build
    //true or false 

    const artifact_name = core.getInput('artifact_name', {required: false} );
    parameters['artifact_name'] = artifact_name
    //string 

    return parameters;
}

export async function run(): Promise<void> {

    const parameters = getInputParameters()
    
    
    const github_workspace = process.env.GITHUB_WORKSPACE;
    const runner_temp = process.env.RUNNER_TEMP;

    core.info(`GITHUB_WORKSPACE:= ${github_workspace}`)
    core.info(`RUNNER_TEMP:= ${runner_temp}`)

    const workflow_app = core.getInput('workflow_app', {required: false} )
    const platformType = core.getInput('platformType', {required: false} )

    downloadJar()
    let scanCommandValue = await checkParameters(parameters)

    core.debug('---- DEBUG OUTPUT START ----')
    core.debug('---- index.ts / run() before run ----')
    core.debug('---- Pipeline Scan Command: '+ scanCommandValue)
    core.debug('---- DEBUG OUTPUT END ----')

    core.debug('Running the Pipeline Scan')
    let scanCommandOutput = await runScan( scanCommandValue, parameters)

    core.debug('Pipeline Scan Output')
    core.debug( scanCommandOutput )

    //check if the results files exist and if not create empty files
    if ( !existsSync('results.json') ){
        core.info('results.json does not exist - creating empty file')
        let emptyResults = {
            "findings": []
        }
        let emptyResultsString = JSON.stringify(emptyResults)
        let emptyResultsFile = 'results.json'
        let emptyResultsFilteredFile = 'filtered_results.json'

        try {
            writeFileSync(emptyResultsFile,emptyResultsString)
        } catch (error) {
            core.warning('Error creating empty results files')
        }
    }

    const rootDirectory = process.cwd()
    core.debug('---- DEBUG OUTPUT START ----')
    core.debug('---- index.ts / run() before create artifacts ----')
    core.debug('---- Root folder: '+ rootDirectory)
    core.debug('---- Results Json File: '+rootDirectory+'/'+parameters.json_output_file)
    core.debug('---- Filtered Results Json File: '+rootDirectory+'/'+parameters.filtered_json_output_file)
    core.debug('---- Summary Output File: '+rootDirectory+'/'+parameters.summary_output_file)
    core.debug('---- DEBUG OUTPUT END ----')


    //const { DefaultArtifactClient } = require('@actions/artifact');
    //const artifactV1 = require('@actions/artifact-v1');
    let artifactClient;

    if (platformType === 'ENTERPRISE') {
        core.debug(`Platform Type: Enterprise`);
        artifactClient = artifactV1.create();
        core.debug(`Initialized the artifact object using version V1.`);
    } else {
        artifactClient = new DefaultArtifactClient();
        core.debug(`Initialized the artifact object using version V2.`);
    }

    
    //check if results files exists and if so store them as artifacts
    if ( existsSync(rootDirectory +' /' + 
        parameters.json_output_file && rootDirectory+ '/' + 
        parameters.filtered_json_output_file && rootDirectory + '/' + 
        parameters.summary_output_file) ){

        core.info('Results files exist - storing as artifact')
    
        //store output files as artifacts
        const artifactName = 'Veracode Pipeline-Scan Results - '+parameters.artifact_name;
        const files = [
            parameters.json_output_file,
            parameters.filtered_json_output_file,
            parameters.summary_output_file
        ]


        const rootDirectory = process.cwd()
        const options = {
            continueOnError: true
        }

        try {
            const uploadResult = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, options)
            core.info('Artifact upload result:')
            core.info('File Size: ' + (uploadResult.size != undefined ? uploadResult.size : 0))
        } catch (error) {
            core.notice('Artifact upload failed:')
            core.notice(String(error))
        }

        core.debug('---- DEBUG OUTPUT START ----')
        core.debug('---- index.ts / run() create artifacts ----')
        core.debug('---- Artifact filenames: '+files)
        core.debug('---- DEBUG OUTPUT END ----')

    } else {
        core.notice('Results files do not exist - no artifact to store')
        core.debug(parameters.filtered_json_output_file + ' does not exist - creating empty file')
        let emptyResults = {
            "findings": []
        }
        let emptyResultsString = JSON.stringify(emptyResults)
        let emptyResultsFilteredFile = parameters.filtered_json_output_file

        try {
            writeFileSync(emptyResultsFilteredFile,emptyResultsString)
        } catch (error) {
            core.warning('Error creating empty results files')
        }

        const artifactName = 'Veracode Pipeline-Scan Results - '+parameters.artifact_name;
        const files = [
            parameters.filtered_json_output_file
        ]


        const rootDirectory = process.cwd()
        const options = {
            continueOnError: true
        }

        try {
            const uploadResult = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, options)
            core.info('Artifact upload result:')
            core.info('File Size: ' + (uploadResult.size != undefined ? uploadResult.size : 0))
        } catch (error) {
            core.warning('Artifact upload failed:')
            core.warning(String(error))
        }
    }


    if ( parameters.store_baseline_file == 'true'){
        core.debug('Baseline File should be stored')
        let commitCommandOutput:any = await commitBasline(parameters)
        core.debug('Git Command Output')
        core.debug(commitCommandOutput)
    }

    core.debug('check if we run on a pull request')
    let pullRequest = process.env.GITHUB_REF
    let isPR:any = pullRequest?.indexOf("pull")

    if ( isPR >= 1 ){
        core.debug("This run is part of a PR, should add some PR comment")

        if ( scanCommandOutput.length >= 1 ){
            core.debug('Results are not empty - adding PR comment')

            const context = github.context
            const repository:any = process.env.GITHUB_REPOSITORY
            const token = core.getInput("token")
            const repo = repository.split("/");
            const commentID:any = context.payload.pull_request?.number


            //creating the body for the comment
            let commentBody = scanCommandOutput
            commentBody = commentBody.substring(commentBody.indexOf('Scan Summary'))
            commentBody = commentBody.replace('===\n---','===\n<details><summary>details</summary><p>\n---')
            commentBody = commentBody.replace('---\n\n===','---\n</p></details>\n===')
            commentBody = commentBody.replace(/\n/g,'<br>')
            commentBody = '<br>![](https://www.veracode.com/themes/veracode_new/library/img/veracode-black-hires.svg)<br>' + commentBody

            core.debug('Comment Body ' + commentBody)

            core.debug('---- DEBUG OUTPUT START ----')
            core.debug('---- index.ts / run() check if on PR  ----')
            core.debug('---- Repository: '+repository)
            core.debug('---- Token: '+token)
            core.debug('---- Comment ID: '+commentID)
            //core.debug('---- Context: '+JSON.stringify(context))
            core.debug('---- DEBUG OUTPUT END ----')

            try {
                const octokit = github.getOctokit(token);

                const { data: comment } = await octokit.rest.issues.createComment({
                    owner: repo[0],
                    repo: repo[1],
                    issue_number: commentID,
                    body: commentBody,
                });
                core.info('Adding scan results as comment to PR #' + commentID)
            } catch (error:any) {
                core.debug(error);
            }
        }
        else {
            core.debug('Results are empty - no need to add PR comment')
        }
    }
    else {
        core.debug('We are not running on a pull request')
    }

    if ( parameters.fail_build == "true" && workflow_app == "false"){
        core.debug('Check if we need to fail the build')
        const failureRegex = /FAILURE: Found \d+ issues!/
        let failBuild = failureRegex.test(scanCommandOutput)

        core.debug('---- DEBUG OUTPUT START ----')
        core.debug('---- index.ts / run() check if we need to fail the build ----')
        core.debug('---- Fail build value found : '+failBuild)
        core.debug('---- DEBUG OUTPUT END ----')     


        if ( failBuild ){
            core.notice('There are flaws found that require the build to fail')
            core.setFailed(scanCommandOutput)
        }
    }

}