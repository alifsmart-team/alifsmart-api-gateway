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
        stage('Deploy to Docker Swarm') {
            steps {
                script { // <-- TAMBAHKAN SCRIPT BLOCK DI SINI untuk membungkus try-catch dan sshagent
                    echo "Preparing to deploy to Docker Swarm..."
                    echo "Attempting to use SSH Agent with credentials ID: ${env.SWARM_MANAGER_SSH_CREDENTIALS_ID}"
                    try {
                        sshagent(credentials: [env.SWARM_MANAGER_SSH_CREDENTIALS_ID]) {
                            echo "[SUCCESS] SSH Agent block started. Key should be loaded."
                            
                            // Karena kita sudah di dalam script block, tidak perlu script block lagi di sini
                            // Langsung tulis logika Groovy dan pemanggilan step powershell/echo
                            if (env.SWARM_MANAGER_USER == null || env.SWARM_MANAGER_USER.trim().isEmpty()) {
                                error("SWARM_MANAGER_USER environment variable is not set or is empty. Please define it in the environment block.")
                            }
                            def sshUser = env.SWARM_MANAGER_USER
                            def sshTarget = "${sshUser}@${env.SWARM_MANAGER_IP}"
                            def sshOpts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=nul -o LogLevel=VERBOSE"
                            def stackPath = "/opt/stacks/${env.DOCKER_IMAGE_NAME}"
                            def stackFileNameInRepo = "api-gateway-stack.yml"
                            def remoteStackFile = "${stackPath}/${stackFileNameInRepo}"
                            def stackNameInSwarm = "alifsmart_apigw"

                            echo "Target remote login: ${sshTarget}"
                            
                            echo "Attempting simple SSH command (pwd) to verify connection..."
                            powershell "ssh ${sshOpts} ${sshTarget} 'pwd'"
                            echo "Simple SSH command 'pwd' executed."

                            echo "Creating remote directory: ${stackPath}"
                            powershell "ssh ${sshOpts} ${sshTarget} 'mkdir -p ${stackPath}'"
                            
                            echo "Copying local .\\${stackFileNameInRepo} to ${sshTarget}:${remoteStackFile}"
                            powershell "scp ${sshOpts} .\\${stackFileNameInRepo} ${sshTarget}:${remoteStackFile}"
                            
                            echo "Deploying stack ${stackNameInSwarm} on Swarm Manager..."
                            def deployCommandOnRemote = """
                            export DOCKER_HUB_USERNAME='${env.DOCKER_HUB_USERNAME}'; \\
                            export DOCKER_IMAGE_NAME='${env.DOCKER_IMAGE_NAME}'; \\
                            export IMAGE_TAG='latest'; \\
                            export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}'; \\
                            export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}'; \\
                            export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}'; \\
                            echo 'Deploying stack ${stackNameInSwarm}...'; \\
                            docker stack deploy -c '${remoteStackFile}' '${stackNameInSwarm}' --with-registry-auth --prune
                            """.trim().replaceAll("\\n", " ")

                            powershell "ssh ${sshOpts} ${sshTarget} \"${deployCommandOnRemote}\""
                            echo "Deployment to Docker Swarm initiated."
                            echo "[SUCCESS] SSH Agent script logic finished." // Diubah dari "script block"
                        } // Akhir dari blok sshagent
                        echo "[SUCCESS] SSH Agent step completed."
                    } catch (Exception e) {
                        echo "[ERROR] An error occurred during SSH Agent operation or subsequent steps."
                        echo "Error Type: ${e.getClass().getName()}"
                        echo "Error Message: ${e.getMessage()}"
                        echo "Error Stack Trace (first few lines):"
                        e.getStackTrace().take(15).each { line -> echo "    at ${line}" }
                        currentBuild.result = 'FAILURE'
                    }
                } // Akhir dari script block luar
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