#!/bin/bash

set -o errexit
set -o pipefail

LENSES_BASE_VERSION=3.2
LENSES_VERSION=3.2.1
LENSES_ARCHIVE=lenses-$LENSES_VERSION-linux64.tar.gz
LENSES_ARCHIVE_URI="https://archive.landoop.com/lenses/$LENSES_BASE_VERSION/$LENSES_ARCHIVE"
TMP_DIR="/tmp"

while getopts n:l: optname; do
  case $optname in
    n)
      CLUSTER_NAME="${OPTARG}";;
    l)
      LICENSE="${OPTARG}";;
  esac
done

# Ambari Watch Dog Username and Password since user's username/password are not passed from the HDI app deployment template
CLUSTER_ADMIN=$(python - <<'CLUSTER_ADMIN_END'
import hdinsight_common.Constants as Constants
print Constants.AMBARI_WATCHDOG_USERNAME
CLUSTER_ADMIN_END
)

CLUSTER_PASSWORD=$(python - <<'CLUSTER_PASSWORD_END'
import hdinsight_common.ClusterManifestParser as ClusterManifestParser
import hdinsight_common.Constants as Constants
import base64

base64pwd = ClusterManifestParser.parse_local_manifest().ambari_users.usersmap[Constants.AMBARI_WATCHDOG_USERNAME].password
print base64.b64decode(base64pwd)
CLUSTER_PASSWORD_END
)

CLUSTER_NAME=$(python - <<'CLUSTER_NAME_END'
import hdinsight_common.ClusterManifestParser as ClusterManifestParser
print ClusterManifestParser.parse_local_manifest().deployment.cluster_name
CLUSTER_NAME_END
)

apt -y install jq

# Fetch Lenses Archive
echo "Fetching Lenses Archive"
wget -q $LENSES_ARCHIVE_URI -P $TMP_DIR

echo "Untar Lenses Archive"
cp $TMP_DIR/$LENSES_ARCHIVE /opt
cd /opt
tar -xzf $LENSES_ARCHIVE
rm -rf /opt/$LENSES_ARCHIVE

# AutoDiscover Kafka Brokers and Zookeeper
echo "AutoDiscover Brokers and Zookeper"
LENSES_KAFKA_BROKERS=$(curl -u $CLUSTER_ADMIN:$CLUSTER_PASSWORD -sS -G "https://$CLUSTER_NAME.azurehdinsight.net/api/v1/clusters/$CLUSTER_NAME/services/KAFKA/components/KAFKA_BROKER" \
    | jq -r '.host_components[].HostRoles.host_name')

if [ -z "${LENSES_KAFKA_BROKERS}"]; then
    echo "[ERROR] Unable to find Cluster Kafka Brokers"         
    exit 1
fi

LENSES_ZOOKEPER=$(curl -u $CLUSTER_ADMIN:$CLUSTER_PASSWORD -sS -G "https://$CLUSTER_NAME.azurehdinsight.net/api/v1/clusters/$CLUSTER_NAME/services/ZOOKEEPER/components/ZOOKEEPER_SERVER" \
    | jq -r '.host_components[].HostRoles.host_name')

# Configure Lenses
chmod -R 0755 lenses
cd lenses

# Make lenses.conf & security.conf empty
mv lenses.conf.sample lenses.conf
mv security.conf.sample security.conf
cat /dev/null > lenses.conf
cat /dev/null > security.conf

cat << EOF > /opt/lenses/lenses.conf
lenses.port=9991

lenses.secret.file=security.conf
lenses.sql.state.dir="kafka-streams-state"
lenses.license.file=license.json
EOF
if [ ! -z "$LENSES_KAFKA_BROKERS" ]; then
    for broker in $LENSES_KAFKA_BROKERS; do
        brokers="${brokers:+$brokers,}PLAINTEXT://$broker:9092"
    done
    echo lenses.kafka.brokers="\"${brokers}\"" >> /opt/lenses/lenses.conf
fi

if [ ! -z "$LENSES_ZOOKEPER" ]; then
    for host in $LENSES_ZOOKEPER; do
        zookeper="${zookeper:+$zookeper, }{url:\"$host:2181\"}"
    done
    echo lenses.zookeeper.hosts="[${zookeper}]" >> /opt/lenses/lenses.conf
fi

# Append Lenses License
cat << EOF > /opt/lenses/license.json
${LICENSE}
EOF

# Systemd service for Lenses
sudo touch /etc/systemd/system/lenses-io.service
sudo bash -c 'cat << EOF > /etc/systemd/system/lenses-io.service
[Unit]
Description=Run Lenses.io Service
;After=opt-lenses.mount
;Requires=opt-lenses.mount

[Service]
Restart=always
User=root
Group=root
LimitNOFILE=4096
PermissionsStartOnly=true

Environment=FORCE_JAVA_HOME="/opt/lenses/jre"
Environment=LT_PACKAGE="azure_hdinsight"
Environment=LT_PACKAGE_VERSION=${LENSES_VERSION}

WorkingDirectory=/opt/lenses
ExecStart=/opt/lenses/bin/lenses lenses.conf

[Install]
WantedBy=multi-user.target
EOF'

sudo systemctl daemon-reload
sudo systemctl restart lenses-io
sudo systemctl enable lenses-io.service
