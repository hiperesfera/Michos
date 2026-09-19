# -*- mode: ruby -*-
# vi: set ft=ruby :

REPO_URL = ENV.fetch("MICHOS_REPO", "https://github.com/hiperesfera/michos")
REPO_REF = ENV.fetch("MICHOS_REF",  "main")
VM_MEM   = ENV.fetch("MICHOS_MEM",  "6144").to_i
VM_CPUS  = ENV.fetch("MICHOS_CPUS", "4").to_i
VM_DISK  = ENV.fetch("MICHOS_DISK", "40")
RUN_BOOTSTRAP = ENV.fetch("MICHOS_BOOTSTRAP", "1") == "1"

Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.hostname = "michos"

  config.vm.network "forwarded_port", guest: 8080,  host: 8080,  auto_correct: true
  config.vm.network "forwarded_port", guest: 5000,  host: 5000,  auto_correct: true
  config.vm.network "forwarded_port", guest: 11434, host: 11434, auto_correct: true

  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.synced_folder "results", "/opt/michos/results", create: true

  if Vagrant.has_plugin?("vagrant-disksize")
    config.disksize.size = "#{VM_DISK}GB"
  end

  if Vagrant.has_plugin?("vagrant-vbguest")
    config.vbguest.auto_update = false
  end

  config.vm.provider "virtualbox" do |vb|
    vb.name   = "michos"
    vb.memory = VM_MEM
    vb.cpus   = VM_CPUS
  end

  config.vm.provider "libvirt" do |lv|
    lv.memory = VM_MEM
    lv.cpus   = VM_CPUS
  end

  config.vm.provision "docker-install", type: "shell", privileged: true, inline: <<-'SHELL'
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
      echo "Docker + compose already installed, skipping."
    else
      apt-get update
      apt-get install -y ca-certificates curl gnupg
      install -m 0755 -d /etc/apt/keyrings
      if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
        curl -fsSL https://download.docker.com/linux/debian/gpg \
          | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
      fi
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
      apt-get update
      apt-get install -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
    fi

    usermod -aG docker vagrant
    systemctl enable --now docker
  SHELL

  config.vm.provision "clone", type: "shell", privileged: true,
    env: { "REPO_URL" => REPO_URL, "REPO_REF" => REPO_REF }, inline: <<-'SHELL'
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y git rsync

    if [ -e /opt/michos/docker-compose.yml ]; then
      echo "Repo already present at /opt/michos, skipping clone."
    else
      rm -rf /tmp/michos-src
      git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" /tmp/michos-src
      mkdir -p /opt/michos
      rsync -a --exclude 'results/' /tmp/michos-src/ /opt/michos/
      rm -rf /tmp/michos-src
      chown -R vagrant:vagrant /opt/michos 2>/dev/null || true
    fi
  SHELL

  if RUN_BOOTSTRAP
    config.vm.provision "bootstrap", type: "shell", privileged: false, inline: <<-'SHELL'
      set -euo pipefail
      sg docker -c "cd /opt/michos && ./bootstrap.sh"
      echo ""
      echo "Done. Open http://localhost:8080 and click 'Log in to Ollama' to finish sign-in."
    SHELL
  end
end
