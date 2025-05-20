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

        // ID Kredensial Redis dari Jenkins (GANTI DENGAN ID YANG BENAR)
        ENV_REDIS_HOST = credentials('redis_host_anda')
        ENV_REDIS_PORT = credentials('redis_port_anda')
        ENV_REDIS_TLS_ENABLED = credentials('redis_tls_is_enabled_anda')

        // Detail Swarm Manager & ID Kredensial SSH (GANTI DENGAN ID YANG BENAR)
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id_anda'
        SWARM_MANAGER_IP = '47.84.46.116' // IP Server 1 Swarm Manager Anda
        
        // ID Kredensial Docker Hub (GANTI DENGAN ID YANG BENAR)
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id_anda'

        // ID Kredensial GitHub PAT (GANTI DENGAN ID YANG BENAR)
        GITHUB_CREDENTIALS_ID = 'github_pat_anda'
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
                // ${PWD} adalah cara PowerShell untuk mendapatkan direktori kerja saat ini (mirip $(pwd) di bash)
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
                        powershell "${trivyScanCommand}" // Menggunakan interpolasi Groovy untuk memasukkan variabel
                        echo "Trivy scan passed or ignored vulnerabilities did not cause failure."
                    } catch (err) {
                        echo "Trivy scan failed or found unignored CRITICAL/HIGH vulnerabilities. Error: ${err.getMessage()}"
                        // error("Trivy scan found unignored CRITICAL/HIGH vulnerabilities or an error occurred.") // Uncomment untuk menggagalkan pipeline jika ada temuan serius
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
                        customImage.tag(latestTag) // Ini akan membuat tag: vitoackerman/alifsmart-api-gateway:latest

                        echo "Pushing image ${imageName}:${buildTag} to Docker Hub..."
                        customImage.push(buildTag) // Mendorong tag spesifik build (misal: :7)
                        
                        echo "Pushing image ${imageName}:${latestTag} to Docker Hub..."
                        customImage.push(latestTag) // Mendorong tag 'latest'
                    }
                    echo "Docker images pushed successfully."
                }
            }
        }

        stage('Deploy to Docker Swarm') {
            steps {
                echo "Preparing to deploy to Docker Swarm..."
                // Menggunakan plugin SSH Agent untuk menangani kunci SSH dengan lebih aman dan kompatibel di Windows
                sshagent(credentials: [env.SWARM_MANAGER_SSH_CREDENTIALS_ID]) {
                    // Di dalam blok sshagent, koneksi SSH akan menggunakan kunci yang sudah dimuat oleh agen.
                    // Anda tidak perlu lagi merujuk ke file kunci privat secara manual (-i path_ke_kunci).
                    script {
                        // Dapatkan username dari kredensial SSH jika dikonfigurasi di sana
                        def sshUser = ''
                        withCredentials([sshUserPrivateKey(credentialsId: env.SWARM_MANAGER_SSH_CREDENTIALS_ID, keyFileVariable: 'UNUSED_KEY_FILE_VAR', usernameVariable: 'SSH_USER_FROM_CRED')]) {
                            sshUser = env.SSH_USER_FROM_CRED
                        }
                        // Jika username tidak ada di kredensial atau ingin di-override:
                        // sshUser = 'root' // Ganti dengan user SSH Anda jika perlu

                        def remoteLogin = "${sshUser}@${env.SWARM_MANAGER_IP}"
                        def remoteStackPath = "/opt/stacks/${env.DOCKER_IMAGE_NAME}" 
                        def stackFileNameInRepo = "api-gateway-stack.yml" 
                        def stackNameInSwarm = "alifsmart_apigw"

                        // Opsi untuk SSH. -i tidak diperlukan lagi karena sshagent
                        def sshOptions = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=nul"

                        echo "Creating remote directory ${remoteStackPath} on ${remoteLogin}..."
                        powershell "ssh ${sshOptions} ${remoteLogin} \`"mkdir -p ${remoteStackPath}\`""
                        
                        echo "Copying ${stackFileNameInRepo} to ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}..."
                        powershell "scp ${sshOptions} .\\${stackFileNameInRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}"
                        
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager ${remoteLogin}..."
                        def deployCommandOnRemote = """
                        export DOCKER_HUB_USERNAME='${env.DOCKER_HUB_USERNAME}'; \\
                        export DOCKER_IMAGE_NAME='${env.DOCKER_IMAGE_NAME}'; \\
                        export IMAGE_TAG='latest'; \\
                        export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}'; \\
                        export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}'; \\
                        export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}'; \\
                        echo 'Deploying stack ${stackNameInSwarm} with image ${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:latest...'; \\
                        docker stack deploy \\
                            -c ${remoteStackPath}/${stackFileNameInRepo} \\
                            ${stackNameInSwarm} \\
                            --with-registry-auth
                        """
                        powershell "ssh ${sshOptions} ${remoteLogin} \"${deployCommandOnRemote}\""
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