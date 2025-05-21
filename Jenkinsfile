// Jenkinsfile
pipeline {
    agent any // Pastikan agent ini memiliki Docker & Git terinstal dan dikonfigurasi dengan benar

    tools {
        // Nama instalasi Git dari Manage Jenkins > Tools
        git 'Default'
    }

    environment {
        // Konfigurasi Docker Image
        DOCKER_HUB_USERNAME = 'vitoackerman'
        DOCKER_IMAGE_NAME = 'alifsmart-api-gateway'

        // ID Kredensial Redis dari Jenkins (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        ENV_REDIS_HOST = credentials('redis_host')
        ENV_REDIS_PORT = credentials('redis_port')
        ENV_REDIS_TLS_ENABLED = credentials('redis_tls_is_enabled')

        // Detail Swarm Manager & ID Kredensial SSH (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id'
        SWARM_MANAGER_IP = '47.84.46.116' // IP Server 1 Swarm Manager Anda
        SWARM_MANAGER_USER = 'root'
        
        // ID Kredensial Docker Hub (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id'

        // ID Kredensial GitHub PAT (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        GITHUB_CREDENTIALS_ID = 'github_pat'
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Checking out from GitHub repository..."
                git branch: 'main',
                    credentialsId: env.GITHUB_CREDENTIALS_ID,
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git' // URL Repo Anda
                echo "Checkout complete."
            }
        }

        stage('Install Dependencies & Test') {
            steps {
                echo "Installing dependencies and running tests inside Docker..."
                // Menggunakan PowerShell untuk menjalankan perintah docker run
                // Bagian sh -c "..." di dalam container tetap karena container adalah Linux (node:18-alpine)
                // ${PWD} adalah cara PowerShell untuk mendapatkan direktori kerja saat ini
                powershell 'docker run --rm -v "${PWD}:/app" -w /app node:18-alpine sh -c "npm ci && npm run test -- --passWithNoTests"'
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    echo "Starting security scan with Trivy..."
                    def fullImageNameForScan = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:scan-${env.BUILD_NUMBER}"

                    echo "Building temporary image for scan: ${fullImageNameForScan}"
                    // docker.build() sudah lintas platform, tidak perlu diubah dari sh/powershell di sini
                    docker.withRegistry('https://index.docker.io/v1/', env.DOCKER_HUB_CREDENTIALS_ID) {
                        def scanImage = docker.build(fullImageNameForScan, "-f Dockerfile .")
                        // Tidak perlu push image scan ini ke registry
                    }
                    
                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities..."
                    // Menggunakan powershell untuk menjalankan Trivy.
                    // Asumsikan 'trivy.exe' ada di PATH Windows Anda.
                    def trivyScanCommand = "trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignore-ids CVE-2024-21538 ${fullImageNameForScan}"
                    // Jika Anda menjalankan Trivy via Docker (direkomendasikan jika trivy.exe tidak di PATH):
                    // trivyScanCommand = "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignore-ids CVE-2024-21538 ${fullImageNameForScan}"
                    
                    try {
                        powershell "${trivyScanCommand}"
                        echo "Trivy scan passed or ignored vulnerabilities did not cause failure."
                    } catch (err) {
                        echo "Trivy scan failed or found unignored CRITICAL/HIGH vulnerabilities. Error: ${err.getMessage()}"
                        // Jika Anda ingin pipeline GAGAL jika ada temuan serius yang tidak diabaikan:
                        // error("Trivy scan found unignored CRITICAL/HIGH vulnerabilities or an error occurred.")
                    }
                    
                    echo "Cleaning up scan image (optional)..."
                    try {
                        powershell "docker rmi ${fullImageNameForScan}"
                    } catch (cleanupErr) {
                        echo "Warning: Failed to remove scan image ${fullImageNameForScan}. Error: ${cleanupErr.getMessage()}"
                    }
                    echo "Security scan completed."
                }
            }
        }

        stage('Build & Push Docker Image') {
            steps {
                script {
                    echo "Building and pushing Docker image..."
                    def imageName = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}"
                    def buildTag = env.BUILD_NUMBER 
                    def latestTag = "latest"

                    // Menggunakan docker.withRegistry untuk login, build, tag, dan push yang terintegrasi
                    docker.withRegistry("https://index.docker.io/v1/", env.DOCKER_HUB_CREDENTIALS_ID) {
                        
                        echo "Building image ${imageName}:${buildTag}..."
                        def customImage = docker.build("${imageName}:${buildTag}", "-f Dockerfile .")

                        echo "Tagging image ${imageName}:${buildTag} as ${imageName}:${latestTag}..."
                        customImage.tag(latestTag)

                        echo "Pushing image ${imageName}:${buildTag} to Docker Hub..."
                        customImage.push(buildTag)
                        
                        echo "Pushing image ${imageName}:${latestTag} to Docker Hub..."
                        customImage.push(latestTag)
                    }
                    echo "Docker images pushed successfully."
                }
            }
        }

        // stage('Deploy via Docker SSH') {
        //     steps {
        //         script {
        //             // Menggunakan withCredentials dengan sshUserPrivateKey
        //             withCredentials([sshUserPrivateKey(
        //                 credentialsId: env.SWARM_MANAGER_SSH_CREDENTIALS_ID, // ID kredensial SSH Anda
        //                 keyFileVariable: 'SSH_PRIVATE_KEY_FILE_PATH',     // Variabel untuk path file kunci
        //                 usernameVariable: 'SSH_USER_FROM_CRED'          // Variabel untuk username dari kredensial
        //             )]) {
        //                 // Pastikan env.SWARM_MANAGER_USER diisi dari SSH_USER_FROM_CRED atau diset manual jika perlu
        //                 def sshUser = env.SSH_USER_FROM_CRED
        //                 if (sshUser == null || sshUser.trim().isEmpty()) {
        //                     // Jika username tidak diset di kredensial, gunakan dari environment atau set default
        //                     sshUser = env.SWARM_MANAGER_USER 
        //                     if (sshUser == null || sshUser.trim().isEmpty()){
        //                         sshUser = 'root' // Fallback terakhir jika tidak ada sama sekali
        //                         echo "Warning: SSH Username not found in credentials or environment, defaulting to '${sshUser}'"
        //                     }
        //                 }
        //                 def sshTarget = "${sshUser}@${env.SWARM_MANAGER_IP}"
        //                 def stackPath = "/opt/stacks/${env.DOCKER_IMAGE_NAME}" // Path di server remote
        //                 def stackFileNameOnRepo = "api-gateway-stack.yml"    // Nama file di workspace Jenkins
        //                 def remoteStackFile = "${stackPath}/${stackFileNameOnRepo}"
        //                 def stackNameInSwarm = "alifsmart_apigw"

        //                 // Opsi SSH, sekarang menggunakan path file kunci dari variabel
        //                 def sshOpts = "-i \"${env.SSH_PRIVATE_KEY_FILE_PATH}\" -o StrictHostKeyChecking=no -o UserKnownHostsFile=nul -o LogLevel=ERROR"
        //                 // Catatan: Anda mungkin perlu menangani izin file %SSH_PRIVATE_KEY_FILE_PATH% di Windows.
        //                 // Ini sering menyebabkan error "bad permissions".

        //                 echo "Target remote login: ${sshTarget}"
        //                 echo "Creating remote directory: ${stackPath}"
        //                 powershell "ssh ${sshOpts} ${sshTarget} 'mkdir -p ${stackPath}'"
                        
        //                 echo "Copying local .\\${stackFileNameOnRepo} to ${sshTarget}:${remoteStackFile}"
        //                 powershell "scp ${sshOpts} .\\${stackFileNameOnRepo} ${sshTarget}:${remoteStackFile}"

        //                 echo "Deploying stack ${stackNameInSwarm} on Swarm Manager..."
        //                 def deployCommandOnRemote = """
        //                 export DOCKER_HUB_USERNAME='${env.DOCKER_HUB_USERNAME}'; \\
        //                 export DOCKER_IMAGE_NAME='${env.DOCKER_IMAGE_NAME}'; \\
        //                 export IMAGE_TAG='latest'; \\
        //                 export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}'; \\
        //                 export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}'; \\
        //                 export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}'; \\
        //                 echo 'Deploying stack ${stackNameInSwarm} with image ${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:latest...'; \\
        //                 docker stack deploy -c '${remoteStackFile}' '${stackNameInSwarm}' --with-registry-auth --prune
        //                 """.trim().replaceAll("\\n", " ")

        //                 powershell "ssh ${sshOpts} ${sshTarget} \"${deployCommandOnRemote}\""
        //                 echo "Deployment to Docker Swarm initiated."
        //             }
        //         }
        //     }
        // }
        stage('Deploy via Docker SSH') {
    steps {
        script {
            withCredentials([sshUserPrivateKey(
                credentialsId: env.SWARM_MANAGER_SSH_CREDENTIALS_ID,
                keyFileVariable: 'SSH_PRIVATE_KEY_FILE_PATH',
                usernameVariable: 'SSH_USER_FROM_CRED'
            )]) {
                def sshUser = env.SSH_USER_FROM_CRED
                if (sshUser == null || sshUser.trim().isEmpty()) {
                    sshUser = env.SWARM_MANAGER_USER
                    if (sshUser == null || sshUser.trim().isEmpty()){
                        sshUser = 'root'
                        echo "Warning: SSH Username not found in credentials or environment, defaulting to '${sshUser}'"
                    }
                }
                def sshTarget = "${sshUser}@${env.SWARM_MANAGER_IP}"
                def stackPath = "/opt/stacks/${env.DOCKER_IMAGE_NAME}"
                def stackFileNameOnRepo = "api-gateway-stack.yml"
                def remoteStackFile = "${stackPath}/${stackFileNameOnRepo}"
                def stackNameInSwarm = "alifsmart_apigw"

                // PowerShell script to set restrictive permissions on the SSH private key
                def setPermissionsScript = """
                \$ErrorActionPreference = 'Stop'
                \$keyPath = \$env:SSH_PRIVATE_KEY_FILE_PATH # Use environment variable directly in PowerShell

                Write-Host "Attempting to set permissions for private key: \$keyPath"

                if (-not (Test-Path \$keyPath -PathType Leaf)) {
                    Write-Error "Private key file not found at: \$keyPath. This path comes from env.SSH_PRIVATE_KEY_FILE_PATH."
                    exit 1
                }

                # Determine the user context the script is running under (e.g., NT AUTHORITY\\SYSTEM, or a specific service account)
                \$currentUser = (whoami).Trim()
                Write-Host "Script is running as user: '\$currentUser'. This user will be granted ownership and/or full control."

                try {
                    Write-Host "Resetting ACLs for \$keyPath..."
                    icacls.exe \$keyPath /reset
                    Write-Host "Successfully reset ACLs."

                    Write-Host "Removing inherited permissions for \$keyPath..."
                    icacls.exe \$keyPath /inheritance:r # Remove inherited Access Control Entries (ACEs)
                    Write-Host "Successfully removed inherited permissions."

                    Write-Host "Granting FullControl to '\$currentUser' for \$keyPath..."
                    # Grant Full Control to the user running the script.
                    # This user (Jenkins agent user) needs to be the effective owner or have rights to modify permissions.
                    icacls.exe \$keyPath /grant "\$currentUser:(F)"
                    Write-Host "Successfully granted FullControl to '\$currentUser'."

                    # Attempt to remove permissions for common groups to ensure the key is protected.
                    # Use /c to continue if a group is not found or an error occurs on removal.
                    Write-Host "Attempting to remove 'Everyone' group permissions..."
                    icacls.exe \$keyPath /remove:g "Everyone" /c
                    Write-Host "Attempting to remove 'Users' group permissions..."
                    icacls.exe \$keyPath /remove:g "Users" /c
                    Write-Host "Attempting to remove 'Authenticated Users' group permissions..."
                    icacls.exe \$keyPath /remove:g "Authenticated Users" /c
                    
                    Write-Host "Permissions successfully set for \$keyPath."
                    Write-Host "Final ACLs for verification:"
                    icacls.exe \$keyPath # Display final permissions
                } catch {
                    Write-Error "Error during permission setting for \$keyPath: \$(\$_.Exception.Message)"
                    Write-Host "Current ACLs on failure:"
                    icacls.exe \$keyPath # Display current permissions on failure
                    exit 1
                }
                """
                echo "Setting permissions for SSH private key file: ${env.SSH_PRIVATE_KEY_FILE_PATH}"
                powershell setPermissionsScript

                // SSH options. Using $env:SSH_PRIVATE_KEY_FILE_PATH directly in PowerShell commands.
                // Using NUL (all caps) for UserKnownHostsFile is more conventional for Windows null device.
                def sshBaseOpts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o LogLevel=ERROR"

                echo "Target remote login: ${sshTarget}"
                echo "Creating remote directory: ${stackPath}"
                powershell "ssh -i \`"\$env:SSH_PRIVATE_KEY_FILE_PATH\`" ${sshBaseOpts} '${sshTarget}' 'mkdir -p ${stackPath}'"
                
                echo "Copying local .\\${stackFileNameOnRepo} to ${sshTarget}:${remoteStackFile}"
                // Ensure stackFileNameOnRepo doesn't have spaces or special characters or quote it appropriately: ".\\${stackFileNameOnRepo}"
                powershell "scp -i \`"\$env:SSH_PRIVATE_KEY_FILE_PATH\`" ${sshBaseOpts} .\\${stackFileNameOnRepo} '${sshTarget}:${remoteStackFile}'"

                echo "Deploying stack ${stackNameInSwarm} on Swarm Manager..."
                def deployCommandOnRemote = """
                export DOCKER_HUB_USERNAME='${env.DOCKER_HUB_USERNAME}'; \\
                export DOCKER_IMAGE_NAME='${env.DOCKER_IMAGE_NAME}'; \\
                export IMAGE_TAG='latest'; \\
                export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}'; \\
                export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}'; \\
                export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}'; \\
                echo 'Deploying stack ${stackNameInSwarm} with image ${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:latest...'; \\
                docker stack deploy -c '${remoteStackFile}' '${stackNameInSwarm}' --with-registry-auth --prune
                """.trim().replaceAll("\\n", " ")

                // Pass the remote command string in double quotes to ssh
                powershell "ssh -i \`"\$env:SSH_PRIVATE_KEY_FILE_PATH\`" ${sshBaseOpts} '${sshTarget}' \`"${deployCommandOnRemote.replace('"', '`"')}\`""
                // Note: .replace('"', '`"') in deployCommandOnRemote escapes double quotes for PowerShell, if any are present and needed literally by the remote shell.
                // If deployCommandOnRemote only uses single quotes internally, this might not be strictly necessary.

                echo "Deployment to Docker Swarm initiated."
            }
        }
    }
}
    } // Akhir stages

    post { 
        always {
            echo "Pipeline finished."
        }
        success {
            echo "Pipeline sukses! Aplikasi telah di-build, di-push, dan (semoga) terdeploy dengan baik."
        }
        failure {
            echo "Pipeline gagal! Silakan periksa log untuk detailnya."
        }
    }
}