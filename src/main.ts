import { readFileSync, existsSync, fstat, writeFileSync } from "fs";
import * as github from "@actions/github";
import * as core from "@actions/core";
import path from "path";
import { DefaultArtifactClient } from "@actions/artifact";
import * as artifactV1 from "@actions/artifact-v1";
import { downloadJar } from "./pipeline-scan";
import { runScan } from "./pipeline-scan";
import { checkParameters } from "./check-parameters";
import { commitBasline } from "./commit";
import { json } from "stream/consumers";
import { stringify } from "querystring";
import { env } from "process";
import { GitHub } from "@actions/github/lib/utils";

function getInputParameters() {
  // get input params
  let parameters: any = {};

  const vid = core.getInput("vid", { required: true });
  parameters["vid"] = vid;

  const vkey = core.getInput("vkey", { required: true });
  parameters["vkey"] = vkey;

  const file = core.getInput("file", { required: true });
  parameters["file"] = file;

  /*
    const run_method = core.getInput('run_method', {required: true} );
    parameters['run_method'] = run_method
    */

  const veracode_policy_name = core.getInput("veracode_policy_name", {
    required: false,
  });
  parameters["veracode_policy_name"] = veracode_policy_name;

  const request_policy = core.getInput("request_policy", { required: false });
  parameters["request_policy"] = request_policy;

  const fail_on_severity = core.getInput("fail_on_severity", {
    required: false,
  });
  parameters["fail_on_severity"] = fail_on_severity;

  const fail_on_cwe = core.getInput("fail_on_cwe", { required: false });
  parameters["fail_on_cwe"] = fail_on_cwe;

  const baseline_file = core.getInput("baseline_file", { required: false });
  parameters["baseline_file"] = baseline_file;

  const policy_name = core.getInput("policy_name", { required: false });
  parameters["policy_name"] = policy_name;

  const policy_file = core.getInput("policy_file", { required: false });
  parameters["policy_file"] = policy_file;

  const timeout = core.getInput("timeout", { required: false });
  parameters["timeout"] = timeout;

  const issue_details = core.getInput("issue_details", { required: false });
  parameters["issue_details"] = issue_details;

  const summary_display = core.getInput("summary_display", { required: false });
  parameters["summary_display"] = summary_display;

  const json_display = core.getInput("json_display", { required: false });
  parameters["json_display"] = json_display;

  const verbose = core.getInput("verbose", { required: false });
  parameters["verbose"] = verbose;

  const summary_output = core.getInput("summary_output", { required: false });
  parameters["summary_output"] = summary_output;

  const summary_output_file = core.getInput("summary_output_file", {
    required: false,
  });
  parameters["summary_output_file"] = summary_output_file;

  const json_output = core.getInput("json_output", { required: false });
  parameters["json_output"] = json_output;

  const include = core.getInput("include", { required: false });
  parameters["include"] = include;

  const json_output_file = core.getInput("json_output_file", {
    required: false,
  });
  parameters["json_output_file"] = json_output_file;

  const filtered_json_output_file = core.getInput("filtered_json_output_file", {
    required: false,
  });
  parameters["filtered_json_output_file"] = filtered_json_output_file;

  const project_name = core.getInput("project_name", { required: false });
  parameters["project_name"] = project_name;

  const project_url = core.getInput("project_url", { required: false });
  parameters["project_url"] = project_url;

  const project_ref = core.getInput("project_ref", { required: false });
  parameters["project_ref"] = project_ref;

  const app_id = core.getInput("app_id", { required: false });
  parameters["app_id"] = app_id;

  const development_stage = core.getInput("development_stage", {
    required: false,
  });
  parameters["development_stage"] = development_stage;

  // const debug = core.getInput('debug', {required: false} );
  // parameters['debug'] = debug

  const store_baseline_file = core.getInput("store_baseline_file", {
    required: false,
  });
  parameters["store_baseline_file"] = store_baseline_file;
  //true or false

  const store_baseline_file_branch = core.getInput(
    "store_baseline_file_branch",
    { required: false }
  );
  parameters["store_baseline_file_branch"] = store_baseline_file_branch;

  const create_baseline_from = core.getInput("create_baseline_from", {
    required: false,
  });
  parameters["create_baseline_from"] = create_baseline_from;
  //standard or filtered

  const fail_build = core.getInput("fail_build", { required: false });
  parameters["fail_build"] = fail_build;
  //true or false

  const artifact_name = core.getInput("artifact_name", { required: false });
  parameters["artifact_name"] = artifact_name;
  //string

  return parameters;
}

function checkIfResultsFilesExist(){
 //check if the results files exist and if not create empty files
  if (!existsSync("results.json")) {
    core.info("results.json does not exist - creating empty file");
    let emptyResults = {
      findings: [],
    };
    let emptyResultsString = JSON.stringify(emptyResults);
    let emptyResultsFile = "results.json";
    let emptyResultsFilteredFile = "filtered_results.json";

    try {
      writeFileSync(emptyResultsFile, emptyResultsString);
    } catch (error) {
      core.warning("Error creating empty results files");
    }
  }
}
function applyPolicy(){}



export async function run(): Promise<void> {
  const parameters = getInputParameters();

  const github_workspace = process.env.GITHUB_WORKSPACE;
  const runner_temp = process.env.RUNNER_TEMP;

  core.info(`GITHUB_WORKSPACE:= ${github_workspace}`);
  core.info(`RUNNER_TEMP:= ${runner_temp}`);

  const workflow_app = core.getInput("workflow_app", { required: false });
  const platformType = core.getInput("platformType", { required: false });

  //Set Download and Unzip the pipeline-scan.jar to be performed in the runner temp directory
  const _currentDir = process.cwd();
  console.debug(`Current working directory: ${_currentDir}`);

  const _tempDir: any = process.env.RUNNER_TEMP;
  console.debug(`Get Temp directory: ${_tempDir}`);
  console.debug(`Check if Temp directory exists: ${existsSync(_tempDir)}`);
  console.debug(`Change directory to Temp directory`);
  const _newDir = process.chdir(_tempDir);
  console.debug(`New working directory: ${process.cwd()}`);

  downloadJar(); //download and unzip the pipeline-scan.jar

  //Change back to the original working directory
  console.debug(
    `Change directory back to original working directory: ${_currentDir}`
  );
  const _backToOriginalDir = process.chdir(_currentDir);
  console.debug(`Current working directory: ${process.cwd()}`);

  let scanCommandValue = await checkParameters(parameters);

  core.debug("---- DEBUG OUTPUT START ----");
  core.debug("---- main.ts / run() before run ----");
  core.debug("---- Pipeline Scan Command to execute: " + scanCommandValue);
  core.debug("---- DEBUG OUTPUT END ----");

  let _binaryPath: string = path.join(_tempDir.toString(), "pipeline-scan.jar");

  core.debug("Running the Pipeline Scan");
  let scanResult = await runScan(`java`,`-jar`, _binaryPath, parameters);
  core.debug("Status Code: " + scanResult.exitCode);
  core.debug("Pipeline Scan Output: "+ scanResult.output.toString());

  //If the scan command output has content no content then something went wrong.
  if(scanResult.exitCode === 0 ){
    core.info("Pipeline-scan completed successfully.");

    //check if results files exist
    checkIfResultsFilesExist();
  
    //compare the results against policy if requested
    if (parameters.request_policy != "" && parameters.request_policy != undefined) {  
      applyPolicy();
    }

  } else {
    core.setFailed("Veracode Pipeline-Scan failed with exit code: " + scanResult.exitCode);
    core.debug("Error Output: " + scanResult.error);
  }
} 
