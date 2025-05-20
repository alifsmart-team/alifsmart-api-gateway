pipeline {
  agent any
  stages {
    stage('Checkout') {
      steps {
        git(branch: 'main', url: 'https://github.com/m4yestik/alifsmart-api-gateway.git')
      }
    }

    stage('Install Dependencies & Test') {
      steps {
        sh 'docker run --rm -v $(pwd):/app -w /app node:18-alpine sh -c "npm ci && npm test"'
      }
    }

    stage('Security Scan (Trivy)') {
      steps {
        script {
          def fullImageNameForScan = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:scan-${env.BUILD_ID}"
          sh "docker build -f Dockerfile -t ${fullImageNameForScan} ." // Tambahkan -f Dockerfile jika nama Dockerfile tidak standar atau untuk kejelasan
          // Gagal_kan pipeline jika ada vulnerability CRITICAL atau HIGH
          sh "trivy image --exit-code 1 --severity CRITICAL,HIGH ${fullImageNameForScan}"
        }

      }
    }

    stage('Build & Push Docker Image') {
      steps {
        script {
          def imageBaseName = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
          def imageWithBuildTag = "${imageBaseName}:${env.BUILD_ID}"
          def imageWithLatestTag = "${imageBaseName}:latest"

          // Login ke Docker Hub menggunakan Jenkins Credentials
          // Pastikan DOCKER_HUB_CREDENTIALS_ID adalah tipe "Username with password"
          withCredentials([usernamePassword(credentialsId: DOCKER_HUB_CREDENTIALS_ID, usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
            sh "echo \"${DOCKER_PASS}\" | docker login -u \"${DOCKER_USER}\" --password-stdin docker.io"
          }

          sh "docker build -f Dockerfile -t ${imageWithBuildTag} ." // Tambahkan -f Dockerfile jika perlu
          sh "docker tag ${imageWithBuildTag} ${imageWithLatestTag}"

          echo "Pushing image ${imageWithBuildTag}..."
          sh "docker push ${imageWithBuildTag}"
          echo "Pushing image ${imageWithLatestTag}..."
          sh "docker push ${imageWithLatestTag}"
        }

      }
    }

    stage('Deploy to Docker Swarm') {
      steps {
        withCredentials(bindings: [sshUserPrivateKey(
                              credentialsId: SWARM_MANAGER_SSH_CREDENTIALS_ID,
                              keyFileVariable: 'SSH_PRIVATE_KEY_FILE', // Variabel Jenkins yang nyimpen path ke private key sementara
                              usernameVariable: 'SSH_USERNAME' // Variabel Jenkins yang nyimpen username dari credential (akan jadi 'root')
                          )]) {
            script {
                echo "Pipeline finished. Starting cleanup (optional)..."
                def imageBaseName = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
                def imageWithBuildTag = "${imageBaseName}:${env.BUILD_ID}"
                def fullImageNameForScan = "${imageBaseName}:scan-${env.BUILD_ID}"

                // Hati-hati dengan `|| true` jika ingin memastikan error cleanup tidak mengganggu status pipeline
                // sh "docker rmi ${imageWithBuildTag} || true" 
                // sh "docker rmi ${fullImageNameForScan} || true"
                // sh "docker image prune -f || true" // Membersihkan dangling images
                echo "Cleanup process finished."
            }
        }
        success {
            echo "Pipeline sukses! API Gateway udah diupdate dan (semoga) terdeploy dengan selamat."
            // Notifikasi ke Slack, Email, dll.
        }
        failure {
            echo "Waduh, pipeline gagal nih, bos! Cek lognya buruan, ada yang gak beres."
            // Notifikasi error
        }
      }

    }
    environment {
      DOCKER_HUB_USERNAME = 'vitoackerman'
      DOCKER_IMAGE_NAME = 'alifsmart-api-gateway'
      ENV_REDIS_HOST = credentials('f80778c6-6904-49cf-8b86-e909905fe4ac')
      ENV_REDIS_PORT = credentials('460e1099-ca40-4918-8d90-7415c4b94b31')
      ENV_REDIS_TLS_ENABLED = credentials('870dd061-f6ba-49dc-8e22-450af5e1d528')
      SWARM_MANAGER_SSH_CREDENTIALS_ID = '0c68d9d8-670b-497f-9106-031cdd2a6eb5'
      SWARM_MANAGER_IP = '47.84.46.116'
      DOCKER_HUB_CREDENTIALS_ID = 'dockerhub-vitoackerman-login'
    }
    post {
      always {
        script {
          def imageBaseName = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
          def imageWithBuildTag = "${imageBaseName}:${env.BUILD_ID}"
          def fullImageNameForScan = "${imageBaseName}:scan-${env.BUILD_ID}"

          echo "Cleaning up Docker images on Jenkins agent (optional)..."
        }

        echo 'Pipeline finished.'
      }

      success {
        echo 'Pipeline sukses! API Gateway udah diupdate dan (semoga) terdeploy dengan selamat.'
      }

      failure {
        echo 'Waduh, pipeline gagal nih, bos! Cek lognya buruan, ada yang gak beres.'
      }

    }
  }