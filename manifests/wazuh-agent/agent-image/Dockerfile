FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y curl procps gnupg apt-transport-https lsb-release python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="placeholder" apt-get install -y wazuh-agent=4.14.1-1 && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install requests kubernetes --break-system-packages 2>/dev/null || pip3 install requests kubernetes

COPY delete-pod.py /var/ossec/active-response/bin/delete-pod.py
RUN chmod 750 /var/ossec/active-response/bin/delete-pod.py && \
    chown root:wazuh /var/ossec/active-response/bin/delete-pod.py

ENTRYPOINT ["/bin/bash"]
