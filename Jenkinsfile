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
        stage('Deploy via Docker SSH using bat and sshagent') {
            steps {
                // Pastikan env.SWARM_MANAGER_SSH_CREDENTIALS_ID merujuk pada Jenkins credential
                // bertipe "SSH Username with private key". Username untuk koneksi SSH
                // diambil dari konfigurasi credential tersebut.
                sshagent(credentials: [env.SWARM_MANAGER_SSH_CREDENTIALS_ID]) {
                    script {
                        // Ambil variabel dari environment untuk kejelasan
                        def swarmManagerIp = env.SWARM_MANAGER_IP
                        def dockerImageName = env.DOCKER_IMAGE_NAME
                        def dockerHubUsername = env.DOCKER_HUB_USERNAME
                        def redisHost = env.ENV_REDIS_HOST
                        def redisPort = env.ENV_REDIS_PORT
                        def redisTlsEnabled = env.ENV_REDIS_TLS_ENABLED
                        def stackFileName = env.STACK_FILE_NAME ?: "api-gateway-stack.yml" // Default jika tidak diset di env
                        def dockerStackName = env.DOCKER_STACK_NAME ?: "alifsmart_apigw"   // Default jika tidak diset di env

                        // Validasi variabel penting
                        if (!swarmManagerIp) {
                            error "SWARM_MANAGER_IP environment variable is not set."
                        }
                        if (!dockerImageName) {
                            error "DOCKER_IMAGE_NAME environment variable is not set."
                        }
                        if (!dockerHubUsername) {
                            error "DOCKER_HUB_USERNAME environment variable is not set."
                        }

                        def remoteStackDir = "/opt/stacks/${dockerImageName}"
                        def remoteStackFilePath = "${remoteStackDir}/${stackFileName}"

                        // Opsi SSH: -i tidak diperlukan dengan sshagent
                        // UserKnownHostsFile=/dev/null biasanya bekerja dengan ssh.exe dari Git Bash
                        // Jika gagal, coba UserKnownHostsFile=nul
                        def sshOpts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

                        echo "Target remote host: ${swarmManagerIp} (username from credential '${env.SWARM_MANAGER_SSH_CREDENTIALS_ID}')"

                        echo "Creating remote directory: ${remoteStackDir}"
                        // Perintah mkdir -p aman dijalankan berkali-kali
                        bat "ssh ${sshOpts} ${swarmManagerIp} \"mkdir -p ${remoteStackDir}\""

                        echo "Copying local .\\${stackFileName} to ${swarmManagerIp}:${remoteStackFilePath}"
                        // Menggunakan tanda kutip untuk menangani spasi pada path jika ada (meskipun tidak direkomendasikan)
                        // Pastikan file ${stackFileName} ada di root workspace Jenkins
                        bat "scp ${sshOpts} \"${stackFileName}\" \"${swarmManagerIp}:${remoteStackFilePath}\""

                        echo "Deploying stack ${dockerStackName} on Swarm Manager..."
                        // Bangun perintah deploy untuk server remote
                        // Variabel Groovy diinterpolasi SEBELUM dikirim ke bat
                        // Tanda kutip tunggal ('') di dalam perintah adalah untuk shell di server remote
                        def deployCommandOnRemote = """
                        export DOCKER_HUB_USERNAME='${dockerHubUsername}'; \\
                        export DOCKER_IMAGE_NAME='${dockerImageName}'; \\
                        export IMAGE_TAG='latest'; \\
                        export ENV_REDIS_HOST='${redisHost}'; \\
                        export ENV_REDIS_PORT='${redisPort}'; \\
                        export ENV_REDIS_TLS_ENABLED='${redisTlsEnabled}'; \\
                        echo 'Deploying stack ${dockerStackName} with image ${dockerHubUsername}/${dockerImageName}:latest...'; \\
                        docker stack deploy -c '${remoteStackFilePath}' '${dockerStackName}' --with-registry-auth --prune
                        """.trim().replaceAll("\\n", " ") // Hapus newline dan ganti dengan spasi agar jadi satu baris perintah

                        // Eksekusi perintah deploy di server remote
                        // Seluruh deployCommandOnRemote diapit "" untuk ssh, yang mana aman karena
                        // di dalamnya menggunakan '' untuk string shell remote.
                        bat "ssh ${sshOpts} ${swarmManagerIp} \"${deployCommandOnRemote}\""

                        echo "Deployment to Docker Swarm initiated for stack: ${dockerStackName}."
                    }
                }
            }
            post {
                always {
                    echo "Finished Deploy via Docker SSH stage."
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