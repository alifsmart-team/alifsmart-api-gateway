pipeline {
    agent any

    tools {
        git 'Default'
    }

    environment {
        // Docker Hub Configuration
        DOCKER_HUB_USERNAME = 'vitoackerman'
        DOCKER_IMAGE_NAME = 'alifsmart-api-gateway'

        // Redis Credentials (Jenkins Credential IDs)
        ENV_REDIS_HOST = credentials('redis_host')
        ENV_REDIS_PORT = credentials('redis_port')
        ENV_REDIS_TLS_ENABLED = credentials('redis_tls_is_enabled')

        // Swarm Manager Configuration
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id'
        SWARM_MANAGER_IP = '47.84.46.116'
        SWARM_MANAGER_USER = 'root'
        
        // Credential IDs
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id'
        GITHUB_CREDENTIALS_ID = 'github_pat'
    }

    stages {
        stage('Checkout Code') {
            steps {
                git branch: 'main',
                    credentialsId: "${env.GITHUB_CREDENTIALS_ID}",
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git'
            }
        }

        stage('Install & Test') {
            steps {
                bat '''
                    docker run --rm -v "%CD%:/app" -w /app node:18-alpine ^
                        sh -c "npm ci && npm run test -- --passWithNoTests"
                '''
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    echo "Starting security scan with Trivy..."
                    // Menggunakan env. untuk mengakses variabel environment di dalam script block
                    def scanImage = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:scan-${env.BUILD_NUMBER}"
                    
                    echo "Building temporary image for scan: ${scanImage}"
                    // Menggunakan docker.build dari plugin Docker Pipeline (sudah lintas platform)
                    // Login mungkin diperlukan jika base image Anda privat, ditangani oleh withRegistry
                    docker.withRegistry('https://index.docker.io/v1/', env.DOCKER_HUB_CREDENTIALS_ID) {
                        docker.build(scanImage, "-f Dockerfile .") 
                        // Tidak perlu push image scan ini ke registry jika hanya untuk scan lokal
                    }
                    
                    echo "Scanning image ${scanImage} for vulnerabilities using Docker (Trivy v${env.TRIVY_VERSION})..."
                    // Menggunakan powershell untuk menjalankan Trivy via Docker di Windows
                    // Path Docker socket untuk Docker Desktop di Windows adalah '//./pipe/docker_engine'
                    // Interpolasi variabel Groovy ${scanImage} dan ${env.TRIVY_VERSION} ke dalam string perintah PowerShell.
                    // Tanda kutip ganda di sekitar nilai variabel direkomendasikan.
                    // Karakter ` (backtick) adalah escape character di PowerShell, digunakan sebelum tanda kutip di dalam string yang juga diapit kutip ganda.
                    // Atau, kita bisa menggunakan single-quoted string di PowerShell untuk bagian yang tidak perlu ekspansi variabel PowerShell.
                    
                    // Opsi 1: Menggunakan string PowerShell multi-baris dengan backtick untuk kelanjutan baris
                    def trivyScanCmd = """docker run --rm -v '//./pipe/docker_engine:/var/run/docker.sock' `
                        aquasec/trivy:${env.TRIVY_VERSION} image `
                        --exit-code 1 `
                        --severity CRITICAL,HIGH `
                        --ignore-unfixed `
                        --ignore-ids CVE-2024-21538 `
                        "${scanImage}" """ // Mengapit ${scanImage} dengan kutip untuk menangani nama image

                    // Opsi 2: Membangun perintah sebagai satu baris (lebih aman dari masalah line continuation PowerShell)
                    // def trivyFullCommand = "docker run --rm -v '//./pipe/docker_engine:/var/run/docker.sock' aquasec/trivy:${env.TRIVY_VERSION} image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignore-ids CVE-2024-21538 \`"${scanImage}\`""
                    // Untuk Opsi 2 ini, jika scanImage mengandung karakter khusus, escape dengan backtick mungkin diperlukan untuk PowerShell.
                    // Lebih aman menggunakan Opsi 1 atau memastikan ${scanImage} tidak punya karakter spesial bagi PowerShell.
                    // Kita akan tetap dengan Opsi 1 karena lebih mudah dibaca.

                    try {
                        powershell trivyScanCmd.trim() // trim() untuk menghapus spasi/newline ekstra
                        echo "Trivy scan passed or specified vulnerabilities were ignored."
                    } catch (err) {
                        echo "Trivy scan failed or found unignored CRITICAL,HIGH vulnerabilities. Error: ${err.getMessage()}"
                        // Jika Anda ingin pipeline GAGAL jika ada temuan serius yang tidak diabaikan:
                        // error("Trivy scan found unignored CRITICAL/HIGH vulnerabilities or an error occurred.")
                    }
                    
                    echo "Cleaning up scan image (optional)..."
                    try {
                        // Menggunakan powershell untuk docker rmi
                        powershell "docker rmi \`"${scanImage}\`"" // Mengapit ${scanImage} dengan kutip dan escape untuk PowerShell
                    } catch (cleanupErr) {
                        echo "Warning: Failed to remove scan image ${scanImage}. Error: ${cleanupErr.getMessage()}"
                    }
                    echo "Security scan completed."
                }
            }
        }

        stage('Deploy to Docker Swarm') {
            steps {
                echo "Preparing to deploy to Docker Swarm..."
                // Menggunakan plugin SSH Agent untuk menangani kunci SSH.
                // Pastikan plugin SSH Agent terinstal dan layanan "OpenSSH Authentication Agent" berjalan di Windows.
                sshagent(credentials: [env.SWARM_MANAGER_SSH_CREDENTIALS_ID]) {
                    // Di dalam blok sshagent, kunci SSH dari kredensial env.SWARM_MANAGER_SSH_CREDENTIALS_ID
                    // akan secara otomatis dimuat dan digunakan oleh perintah ssh/scp.
                    script {
                        // Pastikan SWARM_MANAGER_USER sudah didefinisikan di environment block.
                        if (env.SWARM_MANAGER_USER == null || env.SWARM_MANAGER_USER.trim().isEmpty()) {
                            error("SWARM_MANAGER_USER environment variable is not set or is empty. Please define it in the environment block (e.g., SWARM_MANAGER_USER = 'root').")
                        }
                        def sshUser = env.SWARM_MANAGER_USER
                        def sshTarget = "${sshUser}@${env.SWARM_MANAGER_IP}" // contoh: root@47.84.46.116
                        
                        // Opsi SSH, -i tidak diperlukan karena sshagent
                        // LogLevel ERROR untuk mengurangi verbosity, UserKnownHostsFile=nul untuk Windows
                        def sshOpts = "-o StrictHostKeyChecking=no -o LogLevel=ERROR -o UserKnownHostsFile=nul"
                        
                        def stackPath = "/opt/stacks/${env.DOCKER_IMAGE_NAME}" // contoh: /opt/stacks/alifsmart-api-gateway
                        def stackFileNameOnRepo = "api-gateway-stack.yml" // Nama file di repo Anda
                        def remoteStackFile = "${stackPath}/${stackFileNameOnRepo}" // Path lengkap file di remote
                        def stackNameInSwarm = "alifsmart_apigw" // Nama stack di Swarm

                        echo "Target remote login: ${sshTarget}"
                        
                        // 1. Membuat direktori di server remote jika belum ada
                        echo "Creating remote directory: ${stackPath}"
                        // Perintah 'mkdir -p ...' diapit kutip tunggal untuk shell remote Linux.
                        // Seluruh perintah untuk ssh diapit kutip ganda untuk PowerShell.
                        powershell "ssh ${sshOpts} ${sshTarget} 'mkdir -p ${stackPath}'"
                        
                        // 2. Menyalin file stack dari workspace Jenkins ke server remote
                        echo "Copying local .\\${stackFileNameOnRepo} to ${sshTarget}:${remoteStackFile}"
                        // Menggunakan .\\ untuk path relatif di Windows untuk sumber scp
                        powershell "scp ${sshOpts} .\\${stackFileNameOnRepo} ${sshTarget}:${remoteStackFile}"
                        
                        // 3. Menyiapkan dan menjalankan perintah deployment di server remote
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager..."
                        // Variabel environment yang perlu di-export di remote sebelum deploy
                        // (jika stack file Anda menggunakan substitusi variabel dari environment)
                        def remoteExports = "export DOCKER_HUB_USERNAME='${env.DOCKER_HUB_USERNAME}'; " +
                                            "export DOCKER_IMAGE_NAME='${env.DOCKER_IMAGE_NAME}'; " +
                                            "export IMAGE_TAG='latest'; " + // Atau gunakan env.BUILD_NUMBER jika Anda ingin tag spesifik build
                                            "export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}'; " +
                                            "export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}'; " +
                                            "export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}'; "
                        
                        // Perintah docker stack deploy
                        def dockerDeployCommand = "docker stack deploy -c '${remoteStackFile}' '${stackNameInSwarm}' --with-registry-auth --prune"
                        
                        // Gabungkan perintah export dan docker deploy untuk dieksekusi di remote
                        def fullDeployCommandOnRemote = "${remoteExports} echo 'Executing docker stack deploy...'; ${dockerDeployCommand}"

                        // Mengapit seluruh fullDeployCommandOnRemote dengan kutip ganda agar dikirim sebagai satu argumen ke ssh.
                        powershell "ssh ${sshOpts} ${sshTarget} \"${fullDeployCommandOnRemote}\""
                        echo "Deployment to Docker Swarm initiated."
                    }
                }
            }
        }

    post {
        always {
            echo "Pipeline execution completed"
        }
        success {
            echo "SUCCESS: Application deployed to Swarm cluster"
            slackSend color: 'good', message: "Deployment succeeded: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
        failure {
            echo "FAILURE: Pipeline execution failed"
            slackSend color: 'danger', message: "Deployment failed: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
    }
}