import { readFileSync, existsSync} from 'fs';
import * as core from '@actions/core'
import {create, UploadOptions} from '@actions/artifact'
import { downloadJar } from "./pipeline-scan";
import { runScan } from "./pipeline-scan";
import { checkParameters } from './check-parameters';
import { commitBasline } from './commit';
import { json } from 'stream/consumers';
import { stringify } from 'querystring';
import { env } from "process";
import * as github from '@actions/github'

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

/*
const json_output_file = core.getInput('json_output_file', {required: false} );
parameters['json_output_file'] = json_output_file

const filtered_json_output_file = core.getInput('filtered_json_output_file', {required: false} );
parameters['filtered_json_output_file'] = filtered_json_output_file
*/

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

const debug = core.getInput('debug', {required: false} );
parameters['debug'] = debug

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





async function run (parameters:any){
    downloadJar()
    let scanCommandValue = await checkParameters(parameters)

    if (parameters.debug == 1 ){
        core.info('---- DEBUG OUTPUT START ----')
        core.info('---- index.ts / run() before run ----')
        core.info('---- Pipeline Scan Command: '+scanCommandValue)
        core.info('---- DEBUG OUTPUT END ----')
    }

    core.info('Running the Pipeline Scan')
    let scanCommandOutput = await runScan(scanCommandValue,parameters)

    core.info('Pipeline Scan Output')
    core.info(scanCommandOutput)

    //store output files as artifacts
    const artifact = require('@actions/artifact');
    const artifactClient = artifact.create()
    const artifactName = 'Veracode Pipeline-Scan Results';
    const files = [
        'results.json',
        'filtered_results.json'
    ]

    const rootDirectory = process.cwd()
    const options = {
        continueOnError: true
    }

    const uploadResult = await artifactClient.uploadArtifact(artifactName, files, rootDirectory, options)


    if ( parameters.store_baseline_file == 'true'){
        core.info('Baseline File should be stored')
        let commitCommandOutput:any = await commitBasline(parameters)
        core.info('Git Command Output')
        core.info(commitCommandOutput)
    }

    core.info('check if we run on a pull request')
    let pullRequest = process.env.GITHUB_REF
    let isPR:any = pullRequest?.indexOf("pull")

    if ( isPR >= 1 ){
        core.info("This run is part of a PR, should add some PR comment")

        if ( scanCommandOutput.length >= 1 ){
            core.info('Results are not empty - adding PR comment')

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

            core.info('Comment Body '+commentBody)


            if (parameters.debug == 1 ){
                core.info('---- DEBUG OUTPUT START ----')
                core.info('---- index.ts / run() check if on PR  ----')
                core.info('---- Repository: '+repository)
                core.info('---- Token: '+token)
                core.info('---- Comment ID: '+commentID)
                //core.info('---- Context: '+JSON.stringify(context))
                core.info('---- DEBUG OUTPUT END ----')
            }

            try {
                const octokit = github.getOctokit(token);

                const { data: comment } = await octokit.rest.issues.createComment({
                    owner: repo[0],
                    repo: repo[1],
                    issue_number: commentID,
                    body: commentBody,
                });
                core.info('Adding scan results as comment to PR #'+commentID)
            } catch (error:any) {
                core.info(error);
            }
        }
        else {
            core.info('Results are empty - no need to add PR comment')
        }
    }
    else {
        core.info('We are not running on a pull request')
    }

    if ( parameters.fail_build == "true" ){
        core.info('Check if we need to fail the build')
        let failBuild = scanCommandOutput.indexOf("FAILURE")

        if (parameters.debug == 1 ){
            core.info('---- DEBUG OUTPUT START ----')
            core.info('---- index.ts / run() check if we need to fail the build ----')
            core.info('---- Fail build value found : '+failBuild)
            core.info('---- DEBUG OUTPUT END ----')     
        }


        if ( failBuild >= 1 ){
            core.info('There are flaws found that require the build to fail')
            core.setFailed(scanCommandOutput)
        }
    }

}

run(parameters)