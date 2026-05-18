# SmolerSAST — Integração com Azure DevOps

## Pipeline YAML

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UseDotNet@2
    inputs:
      version: '9.0.x'

  - script: dotnet tool install --global SmolerSAST --version 0.2.0
    displayName: 'Install SmolerSAST'

  - script: smolersast scan --path ./src --output $(Build.ArtifactStagingDirectory)/results.sarif --format both
    displayName: 'Run SmolerSAST scan'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)
      artifactName: 'security-scan'
    condition: always()
```

## Integração com SARIF Viewer

O SARIF gerado é compatível com a extensão "SARIF SAST Scans Tab" do Azure DevOps Marketplace.
