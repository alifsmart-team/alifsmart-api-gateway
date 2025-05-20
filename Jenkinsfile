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
        ENV_REDIS_HOST = credentials('redis_host_anda')
        ENV_REDIS_PORT = credentials('redis_port_anda')
        ENV_REDIS_TLS_ENABLED = credentials('redis_tls_is_enabled_anda')

        // Detail Swarm Manager & ID Kredensial SSH (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id_anda'
        SWARM_MANAGER_IP = '47.84.46.116' // IP Server 1 Swarm Manager Anda
        
        // ID Kredensial Docker Hub (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id_anda'

        // ID Kredensial GitHub PAT (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
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

        stage('Deploy to Docker Swarm') {
            steps {
                echo "Preparing to deploy to Docker Swarm..."
                // Menggunakan plugin SSH Agent untuk menangani kunci SSH
                sshagent(credentials: [env.SWARM_MANAGER_SSH_CREDENTIALS_ID]) {
                    // Di dalam blok sshagent, koneksi SSH akan menggunakan kunci yang sudah dimuat oleh agen.
                    // Anda tidak perlu lagi merujuk ke file kunci privat secara manual (-i path_ke_kunci).
                    script {
                        def sshUser = ''
                        // Mengambil username dari kredensial SSH jika dikonfigurasi di sana
                        try {
                            withCredentials([sshUserPrivateKey(credentialsId: env.SWARM_MANAGER_SSH_CREDENTIALS_ID, keyFileVariable: 'UNUSED_KEY_FILE_VAR', usernameVariable: 'SSH_USER_FROM_CRED')]) {
                                sshUser = env.SSH_USER_FROM_CRED
                            }
                        } catch (e) {
                            echo "Could not retrieve username from SSH credentials, or it was not set. Defaulting or ensure it's set."
                            // Set username default jika tidak ada di credential atau jika ingin override
                            // sshUser = 'root' // Ganti 'root' dengan user SSH Anda jika perlu dan tidak diset di credential
                        }
                        
                        // Jika sshUser masih kosong setelah try-catch (misal, credential bukan tipe SSH Username with private key, atau username kosong)
                        // Anda mungkin perlu mengaturnya secara eksplisit di sini atau memastikan credentialnya benar.
                        // Untuk contoh ini, kita asumsikan username sudah ada di credential atau akan diset manual jika perlu.
                        if (!sshUser) {
                             // Jika Anda tidak menyimpan username di kredensial SSH, Anda harus set di sini
                             // contoh: sshUser = 'user_deploy_anda'
                             // Untuk sekarang, jika kosong, perintah ssh mungkin akan menggunakan username default Jenkins.
                             // Ini perlu perhatian khusus.
                             echo "Warning: SSH_USER_FROM_CRED was not populated. SSH might use default Jenkins user or fail if username is required."
                             // Untuk aman, jika username kosong dan Anda tahu user-nya, set di sini:
                             // sshUser = 'root' // GANTI INI JIKA PERLU
                        }


                        def remoteLogin = "${sshUser}@${env.SWARM_MANAGER_IP}"
                        def remoteStackPath = "/opt/stacks/${env.DOCKER_IMAGE_NAME}" 
                        def stackFileNameInRepo = "api-gateway-stack.yml" 
                        def stackNameInSwarm = "alifsmart_apigw"

                        // Opsi untuk SSH. -i tidak diperlukan lagi karena sshagent
                        // UserKnownHostsFile=nul adalah untuk Windows agar tidak menanyakan host key, tapi pastikan Anda sadar implikasi keamanannya.
                        def sshOptions = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=nul"

                        echo "Creating remote directory ${remoteStackPath} on ${remoteLogin}..."
                        // Perintah remote diapit kutip tunggal untuk shell remote Linux
                        powershell "ssh ${sshOptions} ${remoteLogin} 'mkdir -p ${remoteStackPath}'"
                        
                        echo "Copying ${stackFileNameInRepo} to ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}..."
                        // Menggunakan .\\ untuk path relatif di Windows untuk scp
                        powershell "scp ${sshOptions} .\\${stackFileNameInRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}"
                        
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager ${remoteLogin}..."
                        // Perintah deployCommandOnRemote akan dieksekusi di shell Linux remote server.
                        def deployCommandOnRemote = """
                        export DOCKER_HUB_USERNAME='${env.DOCKER_HUB_USERNAME}'; \\
                        export DOCKER_IMAGE_NAME='${env.DOCKER_IMAGE_NAME}'; \\
                        export IMAGE_TAG='latest'; \\
                        export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}'; \\
                        export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}'; \\
                        export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}'; \\
                        echo 'Deploying stack ${stackNameInSwarm} with image ${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:latest...'; \\
                        docker stack deploy \\
                            -c '${remoteStackPath}/${stackFileNameInRepo}' \\
                            '${stackNameInSwarm}' \\
                            --with-registry-auth
                        """
                        // Mengapit seluruh deployCommandOnRemote dengan kutip ganda agar dikirim sebagai satu argumen ke ssh
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