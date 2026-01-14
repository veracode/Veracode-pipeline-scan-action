function axelF(): void {

  //const rootDirectory = process.cwd();
  // core.debug("---- DEBUG OUTPUT START ----");
  // core.debug("---- index.ts / run() before create artifacts ----");
  // core.debug("---- Root folder: " + rootDirectory);
  // core.debug(
  //   "---- Results Json File: " +
  //     rootDirectory +
  //     "/" +
  //     parameters.json_output_file
  // );
  // core.debug(
  //   "---- Filtered Results Json File: " +
  //     rootDirectory +
  //     "/" +
  //     parameters.filtered_json_output_file
  // );
  // core.debug(
  //   "---- Summary Output File: " +
  //     rootDirectory +
  //     "/" +
  //     parameters.summary_output_file
  // );
  // core.debug("---- DEBUG OUTPUT END ----");

  // //const { DefaultArtifactClient } = require('@actions/artifact');
  // //const artifactV1 = require('@actions/artifact-v1');
  // let artifactClient;

  // if (platformType === "ENTERPRISE") {
  //   core.debug(`Platform Type: Enterprise`);
  //   artifactClient = artifactV1.create();
  //   core.debug(`Initialized the artifact object using version V1.`);
  // } else {
  //   artifactClient = new DefaultArtifactClient();
  //   core.debug(`Initialized the artifact object using version V2.`);
  // }

  // //check if results files exists and if so store them as artifacts
  // if (
  //   existsSync(
  //     rootDirectory + " /" + parameters.json_output_file &&
  //       rootDirectory + "/" + parameters.filtered_json_output_file &&
  //       rootDirectory + "/" + parameters.summary_output_file
  //   )
  // ) {
  //   core.info("Results files exist - storing as artifact");

  //   //store output files as artifacts
  //   const artifactName =
  //     "Veracode Pipeline-Scan Results - " + parameters.artifact_name;
  //   const files = [
  //     parameters.json_output_file,
  //     parameters.filtered_json_output_file,
  //     parameters.summary_output_file,
  //   ];

  //   const rootDirectory = process.cwd();
  //   const options = {
  //     continueOnError: true,
  //   };

  //   try {
  //     const uploadResult = await artifactClient.uploadArtifact(
  //       artifactName,
  //       files,
  //       rootDirectory,
  //       options
  //     );
  //     core.info("Artifact upload result:");
  //     core.info(
  //       "File Size: " + (uploadResult.size != undefined ? uploadResult.size : 0)
  //     );
  //   } catch (error) {
  //     core.notice("Artifact upload failed:");
  //     core.notice(String(error));
  //   }

  //   core.debug("---- DEBUG OUTPUT START ----");
  //   core.debug("---- index.ts / run() create artifacts ----");
  //   core.debug("---- Artifact filenames: " + files);
  //   core.debug("---- DEBUG OUTPUT END ----");
  // } else {
  //   core.notice("Results files do not exist - no artifact to store");
  //   core.debug(
  //     parameters.filtered_json_output_file +
  //       " does not exist - creating empty file"
  //   );
  //   let emptyResults = {
  //     findings: [],
  //   };
  //   let emptyResultsString = JSON.stringify(emptyResults);
  //   let emptyResultsFilteredFile = parameters.filtered_json_output_file;

  //   try {
  //     writeFileSync(emptyResultsFilteredFile, emptyResultsString);
  //   } catch (error) {
  //     core.warning("Error creating empty results files");
  //   }

  //   const artifactName =
  //     "Veracode Pipeline-Scan Results - " + parameters.artifact_name;
  //   const files = [parameters.filtered_json_output_file];

  //   const rootDirectory = process.cwd();
  //   const options = {
  //     continueOnError: true,
  //   };

  //   try {
  //     const uploadResult = await artifactClient.uploadArtifact(
  //       artifactName,
  //       files,
  //       rootDirectory,
  //       options
  //     );
  //     core.info("Artifact upload result:");
  //     core.info(
  //       "File Size: " + (uploadResult.size != undefined ? uploadResult.size : 0)
  //     );
  //   } catch (error) {
  //     core.warning("Artifact upload failed:");
  //     core.warning(String(error));
  //   }
  // }

  // if (parameters.store_baseline_file == "true") {
  //   core.debug("Baseline File should be stored");
  //   let commitCommandOutput: any = await commitBasline(parameters);
  //   core.debug("Git Command Output");
  //   core.debug(commitCommandOutput);
  // }

  // core.debug("check if we run on a pull request");
  // let pullRequest = process.env.GITHUB_REF;
  // let isPR: any = pullRequest?.indexOf("pull");

  // if (isPR >= 1) {
  //   core.debug("This run is part of a PR, should add some PR comment");

  //   if (scanCommandOutput.length >= 1) {
  //     core.debug("Results are not empty - adding PR comment");

  //     const context = github.context;
  //     const repository: any = process.env.GITHUB_REPOSITORY;
  //     const token = core.getInput("token");
  //     const repo = repository.split("/");
  //     const commentID: any = context.payload.pull_request?.number;

  //     //creating the body for the comment
  //     let commentBody = scanCommandOutput;
  //     commentBody = commentBody.substring(commentBody.indexOf("Scan Summary"));
  //     commentBody = commentBody.replace(
  //       "===\n---",
  //       "===\n<details><summary>details</summary><p>\n---"
  //     );
  //     commentBody = commentBody.replace(
  //       "---\n\n===",
  //       "---\n</p></details>\n==="
  //     );
  //     commentBody = commentBody.replace(/\n/g, "<br>");
  //     commentBody =
  //       "<br>![](https://www.veracode.com/themes/veracode_new/library/img/veracode-black-hires.svg)<br>" +
  //       commentBody;

  //     core.debug("Comment Body " + commentBody);

  //     core.debug("---- DEBUG OUTPUT START ----");
  //     core.debug("---- index.ts / run() check if on PR  ----");
  //     core.debug("---- Repository: " + repository);
  //     core.debug("---- Token: " + token);
  //     core.debug("---- Comment ID: " + commentID);
  //     //core.debug('---- Context: '+JSON.stringify(context))
  //     core.debug("---- DEBUG OUTPUT END ----");

  //     try {
  //       const octokit = github.getOctokit(token);

  //       const { data: comment } = await octokit.rest.issues.createComment({
  //         owner: repo[0],
  //         repo: repo[1],
  //         issue_number: commentID,
  //         body: commentBody,
  //       });
  //       core.info("Adding scan results as comment to PR #" + commentID);
  //     } catch (error: any) {
  //       core.debug(error);
  //     }
  //   } else {
  //     core.debug("Results are empty - no need to add PR comment");
  //   }
  // } else {
  //   core.debug("We are not running on a pull request");
  // }

  // if (parameters.fail_build == "true" && workflow_app == "false") {
  //   core.debug("Check if we need to fail the build");
  //   const failureRegex = /FAILURE: Found \d+ issues!/;
  //   let failBuild = failureRegex.test(scanCommandOutput);

  //   core.debug("---- DEBUG OUTPUT START ----");
  //   core.debug("---- index.ts / run() check if we need to fail the build ----");
  //   core.debug("---- Fail build value found : " + failBuild);
  //   core.debug("---- DEBUG OUTPUT END ----");

  //   if (failBuild) {
  //     core.notice("There are flaws found that require the build to fail");
  //     core.setFailed(scanCommandOutput);
  //   }
  // }
};