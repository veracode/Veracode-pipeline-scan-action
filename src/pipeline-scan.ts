#!/usr/bin/env node
import { exec, execSync, spawn } from "child_process";
import * as core from "@actions/core";
import exec1 from "@actions/exec";
import path from "path";
import { countReset } from "console";
import { stringify } from "querystring";
import { stdin } from "process";
import { fstat } from "fs";

export function downloadJar() {
  core.info("Downloading pipeline-scan.jar");
  try {
    var downloadJar = `curl -sSO https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip`;

    if (core.isDebug()) {
    }
    //Debug of CURL
    //curl --output-dir __temp__/ -v -sSO https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip

    var getDownloadOutput = execSync(downloadJar).toString();
    core.info("pipeline-scan.jar downloaded");
  } catch (error: any) {
    core.error(`Status Code: ${error.status} with '${error.message}'`);
  }

  try {
    core.info("Decompressing pipeline-scan-LATEST.zip");
    var unzipJar = "unzip -o pipeline-scan-LATEST.zip";
    const getUnzipOutput = execSync(unzipJar).toString();
    core.info("pipeline_scan.jar unzipped");
  } catch (error: any) {
    core.error(`Status Code: ${error.status} with '${error.message}'`);
    core.warning("Pipeline-scan-LATEST.zip could not be unzipped.");
  }
}

type ScanResult = {
    output: string;
    error: string;
    exitCode: number;
}

export function runScan(jvmRuntimeCmd: string, jvmRuntimeOptoins:string, binaryPath: string, parameters: any) : ScanResult {
  const command = `${jvmRuntimeCmd} ${jvmRuntimeOptoins} ${binaryPath} -v`;
  core.debug("---- pipeline-scan.ts / runScan() ----");
  core.debug("---- Pipeline-scan scan-command: " + command);
  //core.debug('Get Policy File Command Output: '+ commandOutput)

  let scanResult = {} as ScanResult;
  try {
    scanResult.output = execSync(command).toString();
    scanResult.exitCode = 0; // Success
  } catch (ex: any) {
    scanResult.output = ex.stdout?.toString();
    scanResult.error = ex.stderr.toString();
    scanResult.exitCode = ex.status; // Capture the exit code   
  }

  return scanResult;
}

export function getPolicyFile(scanCommand: any, parameters: any) {
  let commandOutput = execSync(scanCommand);

  core.debug("---- DEBUG OUTPUT START ----");
  core.debug("---- pipeline-scan.ts / getPolicyFile() ----");
  core.debug("---- Pipeline-scan get Policy File command: " + scanCommand);
  core.debug("---- Get Policy File Command Output: " + commandOutput);
  core.debug("---- DEBUG OUTPUT END ----");

  return commandOutput;
}
