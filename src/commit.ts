#!/usr/bin/env node
import { exec, execSync, spawn } from "child_process";
import * as core from '@actions/core'
import { env } from "process";



export function commitBasline (parameters:any)  {

    if ( parameters.store_baseline_file_branch == "" || parameters.create_baseline_from == "" ){
        core.debug('To store a baseline file you need to set the parameters "store_baseline_file_branch" and "create_baseline_from" in order to work correctly')
    }
    else {
        core.debug('Creating git command to push file')

        let baselineFileName = ""
        if( parameters.create_baseline_from == "standard"){
            baselineFileName = "results.json"
        }
        else if ( parameters.create_baseline_from == "filtered" ){
            baselineFileName = "filtered_results.json"
        }

        core.debug('Baseline from : '+baselineFileName)
        core.debug('---- DEBUG OUTPUT START ----')
        core.debug('---- commit.ts / commitBasline() ----')
        core.debug('---- Baseline file generated from '+baselineFileName)
        core.debug('---- DEBUG OUTPUT END ----')

        //CI_COMMIT_AUTHOR
        //git pull https://github.com/${process.env.GITHUB_REPOSITORY}.git ${parameters.store_baseline_file_branch}
        //HEAD:${parameters.store_baseline_file_branch}
        //git config pull.rebase true

        /*
        let gitCommand = `  git status
                            git config --global user.name "${ process.env.GITHUB_ACTOR }"
                            git config --global user.email "username@users.noreply.github.com"
                            git checkout -b ${parameters.store_baseline_file_branch}
                            git add "${baselineFileName}"
                            git commit -a -m "Veracode Baseline File push from pipeline"
                            git push -f -u origin ${parameters.store_baseline_file_branch}
                            `
        */

        let gitCommand = `git config --global user.name "${ process.env.GITHUB_ACTOR }"
        git config --global user.email "username@users.noreply.github.com"
        git add "${baselineFileName}"
        git stash push -- ${baselineFileName}
        git pull origin ${parameters.store_baseline_file_branch} || echo "Couldn't find remote branch"
        git checkout stash -- ${baselineFileName}
        git commit -m "Veracode Baseline File push from pipeline"
        git push origin HEAD:${parameters.store_baseline_file_branch} --force-with-lease`

        core.debug('Git Command: '+gitCommand)
        core.debug('---- DEBUG OUTPUT START ----')
        core.debug('---- commit.ts / commitBasline() ----')
        core.debug('---- Git Command: '+gitCommand)
        core.debug('---- DEBUG OUTPUT END ----')
        
        
        let commandOutput = ''
        try {
            execSync(gitCommand)
        } catch (ex:any){
            commandOutput = ex.stdout.toString()
        }
        return commandOutput
    }
}