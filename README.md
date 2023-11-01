# Veracode Pipeline Scan Action

Veracode Pipeline Scan Action runs the Veracode pipeline-scan as an action on any GitHub pipeline

The only pre-requisites is to have the application compiled/packaged according the Veracode Packaging Instructions [here](https://docs.veracode.com/r/compilation_packaging) 

## About

The `pipeline-scan action` is designed to be used in a CI/CD pipeline to submit a binary or source code zip to Veracode for security scanning. It supports scans for Java, JavaScript, Scala, Kotlin, Groovy and Android code.

For more information on Pipeline Scan, visit the [Veracode Docs](https://docs.veracode.com/r/Pipeline_Scan).

## Usage

Intended usage is to add a job to your CI/CD pipeline, after a build job, uploads the "application", scans it and returns the results.  
A build can be failed upon findings, as well the action allows you to generate a new baseline file and commit it back into a different branch of your repository where it can be used to sort out previous findings in order to report on net-new findings. Please refere to the Veracode documentation [here](https://docs.veracode.com/r/Using_a_Pipeline_Scan_Baseline_File).  
  
If the action will run within a PR, it will automatically add a comment with all results to the PR. This is done for easy review and approval processes.  
![](/media/pr-comment.png)  
  
If the parameter `fail_build` is set to `true`, the action will fail the step upon findings. If set to `false`, the step will not show as failed.  
![](/media/fail-build.png)  
  
The full output of the action can still be reviewed on the action run overview and on the command line output.  
 ![](/media/action-overview.png)  
 ![](/media/command-line-output.png)  
   

The tool will need some information passed to it as parameters (many are optional):

* Required
  * vid
    * the Veracode API ID
  * vkey
    * the Veracode API Secret Key
  * file
    * The build artifact file to upload and scan

* Very Common
  * veracode_policy_name
    * Name of the Veracode default policy or custom-built policy to apply to the scan results.
  * request_policy
    * DPERECATED, WILL BE REMOVED WITH NEXT VERSION - The name of the custom platform policy that will be downloaded. A scan will not happen. This can not be a Veracode builtin policy. The name of the policy file is by convention the name of the policy with spaces replaced by underscores and .json appended.
  * fail_on_severity
    * Only fail if flaws of Very High or High severity are found.
  * fail_on_cwe
    * Also fail if a CWE-80: (XSS) flaw is found. (It is Medium severity and thus would be filtered out by the above option)
  * baseline_file:
    * Filter the flaws that exist in the specified baseline file and show only the additional flaws in the current scan.
  * policy_name
    * DPERECATED, WILL BE REMOVED WITH NEXT VERSION - Name of the Veracode default policy rule to apply to the scan results. You can only use this parameter with a Veracode default policy.
  * policy_file:
    * a previously downloaded policy file that should used to rate the findings
  * fail_build:
    * Fail the build upon findings. Takes true or false

* Common
  * timeout
  * issue_details
  * summary_display
  * json_display
  * verbose
  * summary_output
  * summary_output_file
  * json_output
  * json_output_file
  * filtered_json_output_file
  * project_name
  * project_url
  * project_ref
  * app_id
  * development_stage
  * include

* Baseline file
  * if a baseline file should be stored from the scan all paramters are required
  * store_baseline_file
    * TRUE | FALES
  * store_baseline_file_branch:
    * Enter the branch name where the baseline file should be stored
  * create_baseline_from:
    * From which results should the baseline file be created. standard = full results || filtered = filtered results  
  
### ATTENTION  
If you store a baseline file from a pipeline scan the action will commit and push that file to a specified branch on the same repository using these commands:
```sh
git config --global user.name "${ process.env.GITHUB_ACTOR }"  
git config --global user.email "username@users.noreply.github.com"  
git add "${baselineFileName}"  
git stash  
git pull origin ${parameters.store_baseline_file_branch} || echo "Couldn't find remote branch"  
git checkout stash -- .  
git commit -m "Veracode Baseline File push from pipeline"   
git push origin HEAD:${parameters.store_baseline_file_branch} --force-with-lease  
```  
Make sure that doesn't have any side effects on your repository. If you are not sure, don't store the baseline file from the action itself, instead store it as an artifact and commit/push it yourself to the place where it should be stored.  

## Examples  
All examples follow the same strucutre, the will all `need` the `build` to be finished before the they will start running. Veraocde's static analysis is mainly binary static analysis, therefore a compile/build action is required before a pipeline scan can be started. Please read about the packaging and compilation requirements here: https://docs.veracode.com/r/compilation_packaging.  
The examples will checkout the repository, they will download the previously generated build artefact, that is named `verademo.war` and then run the action.  
  

The basic yml  
  
  ```yml 
  pipeline_scan:
      # needs the build step before this job will start running
      needs: build
      runs-on: ubuntu-latest
      name: pipeline scan

      steps:
        - name: checkout repo
          uses: actions/checkout@v3
        
        # get the compiled binary from a previous job
        - name: get archive
          uses: actions/download-artifact@v3
          with:
            name: verademo.war

        # run the pipeline scan action
        - name: pipeline-scan action step
          id: pipeline-scan
          uses: veracode/Veracode-pipeline-scan-action@v1.0.10
          with:
            vid: ${{ secrets.VID }}
            vkey: ${{ secrets.VKEY }}
            file: "verademo.war" 
  ``` 
  

Rate the findings according to a policy and fail the build  
  
  ```yml 
  pipeline_scan:
      # needs the build step before this job will start running
      needs: build
      runs-on: ubuntu-latest
      name: pipeline scan

      steps:
        - name: checkout repo
          uses: actions/checkout@v3
        
        # get the compiled binary from a previous job
        - name: get archive
          uses: actions/download-artifact@v3
          with:
            name: verademo.war

        # run the pipeline scan action
        - name: pipeline-scan action step
          id: pipeline-scan
          uses: veracode/Veracode-pipeline-scan-action@v1.0.10
          with:
            vid: ${{ secrets.VID }}
            vkey: ${{ secrets.VKEY }}
            file: "verademo.war" 
            veracode_policy_name: "VeraDemo Policy"
            fail_build: true
  ```     
  

Sort out previous findings using a baseline file  
  
  ```yml 
  pipeline_scan:
      # needs the build step before this job will start running
      needs: build
      runs-on: ubuntu-latest
      name: pipeline scan

      steps:
        - name: checkout repo
          uses: actions/checkout@v3
        
        # get the compiled binary from a previous job
        - name: get archive
          uses: actions/download-artifact@v3
          with:
            name: verademo.war

        # run the pipeline scan action
        - name: pipeline-scan action step
          id: pipeline-scan
          uses: veracode/Veracode-pipeline-scan-action@v1.0.10
          with:
            vid: ${{ secrets.VID }}
            vkey: ${{ secrets.VKEY }}
            file: "verademo.war" 
            baseline_file: "veracode-pipeline-scan-baseline-file.json"
            fail_build: true
  ```     

  

Sort out previous findings using a baseline file, create a new baseline file and store on a specified branch  
  
  ```yml 
  pipeline_scan:
      # needs the build step before this job will start running
      needs: build
      runs-on: ubuntu-latest
      name: pipeline scan

      steps:
        - name: checkout repo
          uses: actions/checkout@v3
        
        # get the compiled binary from a previous job
        - name: get archive
          uses: actions/download-artifact@v3
          with:
            name: verademo.war

        # run the pipeline scan action
        - name: pipeline-scan action step
          id: pipeline-scan
          uses: veracode/Veracode-pipeline-scan-action@v1.0.10
          with:
            vid: ${{ secrets.VID }}
            vkey: ${{ secrets.VKEY }}
            file: "verademo.war"  
            store_baseline_file: true
            store_baseline_file_branch: my-featur-branch
            create_baseline_from: standard
            baseline_file: "veracode-pipeline-scan-baseline-file.json"
            fail_build: true
  ```     

## Compile the action  
The action comes pre-compiled as transpiled JavaScript. If you want to fork and build it on your own you need NPM to be installed, use `ncc` to compile all node modules into a single file, so they don't need to be installed on every action run. The command to build is simply  

```sh
ncc build ./src/index.ts  
```
