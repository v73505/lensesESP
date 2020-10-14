#!/bin/bash

## Set runtime opts
set -o errexit
set -o pipefail

while getopts n:l:e:u:p:k:j:v:z:x:m:g:q:c:P:a:R:V:J:L:N:I:U: optname; do
  case ${optname} in
    n)
        CLUSTER_NAME="${OPTARG}";;
    V)
        LENSES_VERSION="${OPTARG}";;
    l)
        LICENSE="${OPTARG}";;
    U)
        LENSES_ADMIN_NAME="${OPTARG}";;
    P)
        LENSES_PASSWORD_NAME="${OPTARG}";;
    e)
        ESP_ENABLED="${OPTARG}";;
    c)
        ESP_CREDENTIALS_ENABLED="${OPTARG}";;
    u)
        ESP_USERNAME="${OPTARG}";;
    p)
        ESP_PASSWORD="${OPTARG}";;
    k)
        ESP_KEYTAB_ENABLED="${OPTARG}";;
    v)
        ESP_B64_KEYTAB="${OPTARG}";;
    x)
        ESP_KEYTAB_PRINCIPAL="${OPTARG}";;
    j)
        ESP_JAAS_ENABLED="${OPTARG}";;
    J)
        ESP_B64_JAAS="${OPTARG}";;
    L)
        ESP_KEYTAB_LOCATION="${OPTARG}";;
    N)
        ESP_KEYTAB_NAME="${OPTARG}";;
    a)
        LENSES_CUSTOM_ARCHIVE_ENABLED="${OPTARG}";;
    R)
        LENSES_CUSTOM_ARCHIVE_URL="${OPTARG}";;
    I)
        LENSES_PORT="${OPTARG}";;
    *)
        echo "Option ${optname} is not supported";;
  esac
done

# Configure environmental variables

## Set Lenses Global Environment
## Note: Please do not change these values as they have been set to work with
##       the official name of urls and archives provided by Lenses.io.
##       If you want to use a custom archive that matches the security settings
##       in your organization, then do so by setting the following positional parameters
##       to the script: -a True -R "https://some_url:some_port/some/path"
##
export LENSES_ARCHIVE="lenses-latest-linux64.tar.gz"
export LENSES_ARCHIVE_SHA256="lenses-latest-linux64.tar.gz.sha256"
export LENSES_ARCHIVE_URI="https://archive.landoop.com/lenses/${LENSES_VERSION}/${LENSES_ARCHIVE}"
export LENSES_ARCHIVE_SHA256_URI="https://archive.landoop.com/lenses/${LENSES_VERSION}/${LENSES_ARCHIVE_SHA256}"
export LICENSE_TRIAL="https://milou.lenses/api/lenses-azure-trial"
export TMP_DIR="/tmp"

## Set keyTab location to default /etc/krb5.d in case no parameter was provided
## Also ensure that no trailing / exists if a location string has been provided
if [ -z "${ESP_KEYTAB_LOCATION// }" ]; then
    export ESP_KEYTAB_LOCATION="/etc/krb5.d"
else
    export ESP_KEYTAB_LOCATION="${ESP_KEYTAB_LOCATION%/}"
fi

## Set keyTab name to the default krb5.keytab in no name string has been provided
if [ -z "${ESP_KEYTAB_NAME// }" ]; then
    export ESP_KEYTAB_NAME="krb5.keytab"
fi

## Create ${ESP_KEYTAB_LOCATION} dictionary if it does not exist
## Warning: Please keep ${ESP_KEYTAB_LOCATION} with 0700 permissions.
if [ ! -e "${ESP_KEYTAB_LOCATION}" ]; then
    mkdir -p "${ESP_KEYTAB_LOCATION}"
    chmod -R 0700 "${ESP_KEYTAB_LOCATION}"
else
    if [ ! -d "${ESP_KEYTAB_LOCATION}" ]; then
        echo "Custom keytab path: ${ESP_KEYTAB_LOCATION} does not appear to be a directory. Exiting..."
        exit 1
    fi
fi

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

# Install to system required packages
if ! command -v jq >/dev/null 2>&1 || ! command -v hashalot >/dev/null 2>&1; then
    apt -y install jq hashalot
fi

# Install Lenses

## Fetch sha256sum file from Lenses archive if no custom archive has been
## provided
if [ "${LENSES_CUSTOM_ARCHIVE_ENABLED}" != "True" ]; then
    rm -f "${TMP_DIR}/${LENSES_ARCHIVE_SHA256}"
    wget -q "${LENSES_ARCHIVE_SHA256_URI}" -P "${TMP_DIR}"
fi

## Function for checking sha256sum of Lenses archive
function check_sha256() {
    pushd "${1}" >/dev/null 2>&1
    echo "Checking sha256sum"
    if ! sha256sum -c "${2}" >/dev/null 2>&1; then
        popd >/dev/null 2>&1
        return 1
    fi

    popd >/dev/null 2>&1
    return 0
}

## Download the archive. Here we have 3 cases
## Case-1: Archive does not exit and no custom archive has been requested
##                Here we fetch the archive and run a sha256sums check. No error is allowed
## Case-2: Archive does exist and no custom archive has been requested
##                Here we check if the newely fetched sha256sums file matches the already existing
##                archive. If it does not, we assume a new version for the specific Major.Minor has
##                been released, and we fetch again. If the sha256sums do not match again, we exit
## Case-3: Custom archive has been requested. No sha256sums validation is done
##
if [ ! -f "${TMP_DIR}/${LENSES_ARCHIVE}" ] && [ "${LENSES_CUSTOM_ARCHIVE_ENABLED}" != "True" ]; then
    echo "Fetching Lenses Archive"
    wget -q "${LENSES_ARCHIVE_URI}" -P "${TMP_DIR}"

    if ! check_sha256 "${TMP_DIR}" "${LENSES_ARCHIVE_SHA256}"; then
        echo "Error: sha256 failed verification. Exiting..."
        exit 1
    fi
elif [ -f "${TMP_DIR}/${LENSES_ARCHIVE}" ] && [ "${LENSES_CUSTOM_ARCHIVE_ENABLED}" != "True" ]; then
    echo "Archive already exists"
    ### Validate remote sha256 with the existing archive
    if ! check_sha256 "${TMP_DIR}" "${LENSES_ARCHIVE_SHA256}"; then
        echo "sum256sum do not match. Possibly a new version has been released"
        echo "Fetching new archive"

        rm -f "${TMP_DIR}/${LENSES_ARCHIVE}"
        wget -q "${LENSES_ARCHIVE_URI}" -P "${TMP_DIR}"

        if ! check_sha256 "${TMP_DIR}" "${LENSES_ARCHIVE_SHA256}"; then
            echo "Error: sha256 failed verification. Exiting..."
            exit 1
        fi
    fi
else
    echo "Preparing to fetch custom archive"
    ### Check if a url has been provided.
    if [ -z "${LENSES_CUSTOM_ARCHIVE_URL// }" ]; then
        echo "Custom archive has been enabled but no url was provided"
        exit 1
    fi

    ### Export the archive name from the URL and check from empty string
    export LENSES_ARCHIVE="${LENSES_CUSTOM_ARCHIVE_URL##*/}"

    if [ -n "${LENSES_ARCHIVE// }" ]; then
        rm -f "${TMP_DIR}/${LENSES_ARCHIVE}"
    else
        echo "Can not extract custom archive name."
        exit 1
    fi

    echo "Fetching Archive"
    wget -q "${LENSES_CUSTOM_ARCHIVE_URL}" -P "${TMP_DIR}"
fi


## Extract Lenses archive under ${TMP_DIR}
## Check if /opt/lenses exists. Purge if so
if [ -e /opt/lenses ]; then
    echo "Cleaning up old lenses directory"
    rm -rf /opt/lenses
fi

## Extract the lenses under /opt
echo "Untar Lenses Archive"
tar -xzf "${TMP_DIR}/${LENSES_ARCHIVE}" -C /opt/

## We expect both official Lenses archives and custom archives to contain
## /lenses under the archive root
if [ ! -e /opt/lenses ]; then
    echo "Custom archive root dir is not lenses"
    echo "Error: /opt/lenses does not exist after extracting"
    exit 1
fi

## AutoDiscover Kafka Brokers and Zookeeper
echo "AutoDiscover Brokers and Zookeper"

### Declare an array and populate it with the kafka bootstrap servers
declare -a LENSES_KAFKA_BROKERS=$(curl \
    -u "${CLUSTER_ADMIN}":"${CLUSTER_PASSWORD}" -sS \
    -G "http://headnodehost:8080/api/v1/clusters/${CLUSTER_NAME}/services/KAFKA/components/KAFKA_BROKER" \
    | jq -r '.host_components[].HostRoles.host_name')

if [ -z "${LENSES_KAFKA_BROKERS}" ]; then
    echo "[ERROR] Unable to find Cluster Kafka Brokers"         
    exit 1
fi

### Declare an array and populate it with the zookeeper servers
declare -a LENSES_ZOOKEPER=$(curl \
    -u "${CLUSTER_ADMIN}":"${CLUSTER_PASSWORD}" -sS \
    -G "http://headnodehost:8080/api/v1/clusters/${CLUSTER_NAME}/services/ZOOKEEPER/components/ZOOKEEPER_SERVER" \
    | jq -r '.host_components[].HostRoles.host_name')


## Configure Lenses
chmod -R 0700 /opt/lenses
cd /opt/lenses

### Create lenses.conf & security.conf files
touch lenses.conf
touch security.conf
### Set permissions for both files to 0600
chmod 0600 lenses.conf security.conf

### Check port and set to 9991 in case it is not defined
if [ -z "${LENSES_PORT// }" ]; then
    export LENSES_PORT="9991"
fi

cat << EOF > /opt/lenses/lenses.conf
lenses.port="${LENSES_PORT// }"

lenses.secret.file=security.conf
lenses.sql.state.dir="kafka-streams-state"
lenses.license.file=license.json
EOF

### Check if default admin name has been set. Set to admin otherwise
if [ -z "${LENSES_ADMIN_NAME// }" ]; then
    export LENSES_ADMIN_NAME="admin"
    echo "No Lenses default admin username was provided."
    echo "Setting default username: admin"
fi

### Raise error in case default admin password has not been set
if [ -z "${LENSES_PASSWORD_NAME// }" ]; then
    echo "No Lenses default admin password was provided. Exiting..."
    exit 1
fi

### Keep the permissions of this file 0600
cat << EOF > /opt/lenses/security.conf
lenses.security.user="${LENSES_ADMIN_NAME}"
lenses.security.password="${LENSES_PASSWORD_NAME}"
EOF

### Export Kafka Broker Protocol
if [ "${ESP_ENABLED}" == "False" ]; then
    export KB_PROTOCOL="PLAINTEXT"
elif [ "${ESP_ENABLED}" == "True" ]; then
    export KB_PROTOCOL="SASL_PLAINTEXT"

    echo 'lenses.kafka.settings.client.security.protocol = SASL_PLAINTEXT' \
        >> /opt/lenses/lenses.conf
else
    echo "ESP_ENABLED can only be True or False"
    exit 1
fi

### Configure lenses.kafka.brokers
if [ -n "${LENSES_KAFKA_BROKERS}" ]; then
    for broker in ${LENSES_KAFKA_BROKERS}; do
        brokers="${brokers:+${brokers},}${KB_PROTOCOL}://${broker}:9092"
    done
    echo lenses.kafka.brokers="\"${brokers}\"" >> /opt/lenses/lenses.conf
fi

### Configure lenses.kafka.zookeepers
if [ -n "${LENSES_ZOOKEPER}" ]; then
    for host in ${LENSES_ZOOKEPER}; do
        zookeper="${zookeper:+${zookeper}, }{url:\"${host}:2181\"}"
    done
    echo lenses.zookeeper.hosts="[${zookeper}]" >> /opt/lenses/lenses.conf
fi

### Append Lenses License
cat << EOF > /opt/lenses/license.json
${LICENSE}
EOF
chmod 0600 /opt/lenses/license.json


# Configure systemd services

## Create lenses.env for storing env vars
touch /etc/lenses.env
chmod 0600 /etc/lenses.env

## Systemd service for Kerberos ticket init
## Note: This service uses the action kinit script that
##       is described below in the -- ACTION INIT SCRIPT ---
##       section.
##
## Warning-1: Please read the -- ACTION INIT SCRIPT ---
##            section for additional security info.
##
## Warning-2: Please use a keytab instead of credentials
##
touch /etc/systemd/system/krb-ticket-init.service
cat << EOF > /etc/systemd/system/krb-ticket-init.service
[Unit]
Description=Init a new Kerberos ticket
After=network-online.target

[Service]
Restart=always
User=root
Group=root
ExecStart=/bin/bash -c "/etc/krb5.d/action_kinit.sh"

[Install]
WantedBy=multi-user.target
EOF

## --- KRB5 Ticket Renewal ---
## Systemd service for Kerberos ticket renewal
## Note: This is a simple krenew service which is similar
##       to a kinit -R. The difference here is that kstart
##       runs as a daemon and checks for ticket expiration
##       that is closer to 60min. If that is the case, the
##       the ticket is renewed again. With maximum renewal
##       up to the tickets final expiration date
touch /etc/systemd/system/krb-ticket-renewal.service
cat << EOF > /etc/systemd/system/krb-ticket-renewal.service
[Unit]
Description=Renew Kerberos ticket each 2 min
After=krb-ticket-init.service
Requires=krb-ticket-init.service

[Service]
Restart=always
User=root
Group=root
ExecStart=/usr/bin/krenew -K 60 -v

[Install]
WantedBy=multi-user.target
EOF

## Systemd service for Lenses
touch /etc/systemd/system/lenses-io.service
cat << EOF > /etc/systemd/system/lenses-io.service
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
EnvironmentFile=/etc/lenses.env

WorkingDirectory=/opt/lenses
ExecStart=/opt/lenses/bin/lenses lenses.conf

[Install]
WantedBy=multi-user.target
EOF

## Create /etc/krb5.d dictionary to store esp items if any
## We do this because the user could have used a differet path for
## the keyTab
if [ ! -e "/etc/krb5.d" ]; then
    mkdir -p /etc/krb5.d
    chmod -R 0700 /etc/krb5.d
fi

## -- ACTION INIT SCRIPT ---
## Create the action script which will run a kinit -r7d each 1 day.
## We could go with kinit -r2d since we run each 1 day, but a 7 days
## tickets is reasonable for a service.
## Warning-1: Keep /etc/lenses.env with 0600 permissions. This service
##          runs on background and each one day will do a 
##          print passwoed | kinit principal_name. This can be considered
##          a security risk since other none users can catch that call
##
## Warning-2: Do not use credentials options if the edge node will be
##            accessible by none Kafka administrators.
##
## Warning-3: Only kafka administrators or trusted personel should have 
##            root previlages in the edgenode that runs this script,
##            because the root user will always have a ticket
##            that can access Kafka.
cat << EOF > /etc/krb5.d/action_kinit.sh
while true; do
    source /etc/lenses.env
    echo "\${ESP_PASSWORD}" | kinit -r7d "\${ESP_USERNAME}"
    unset ESP_PASSWORD ESP_USERNAME
    sleep 7200
done
EOF
chmod 0700 /etc/krb5.d/action_kinit.sh

## Create a kafka client jaas file that uses a keytab
## Note-1: This jaas file is always generated, but it 
##         will be used only for the cases where a keytab
##         or a custom jaas has been provided
##
## Note-2: The principal name, keytab location and name
##         need to be set via the following positional
##         parameters: -x Principal -L /some/path -N someName
##
touch /etc/krb5.d/kafka_client_jaas.conf
cat << EOF > /etc/krb5.d/kafka_client_jaas.conf
KafkaClient {
   com.sun.security.auth.module.Krb5LoginModule required
   useKeyTab=true
   storeKey=true
   keyTab="${ESP_KEYTAB_LOCATION}/${ESP_KEYTAB_NAME}"
   principal="${ESP_KEYTAB_PRINCIPAL}"
   serviceName="kafka";
};
Client {
   com.sun.security.auth.module.Krb5LoginModule required
   useKeyTab=true
   storeKey=true
   keyTab="${ESP_KEYTAB_LOCATION}/${ESP_KEYTAB_NAME}"
   principal="${ESP_KEYTAB_PRINCIPAL}"
   serviceName="zookeeper";
};
EOF
chmod 0600 /etc/krb5.d/kafka_client_jaas.conf

## Configure env for ESP
if [ "${ESP_ENABLED}" == "True" ]; then
    echo "Setting ESP env"

    ### Exit if esp is enabled but neither credentials, nor keytab authentication methods was set
    if [ "${ESP_CREDENTIALS_ENABLED}" != "True" ] && [ "${ESP_KEYTAB_ENABLED}" != "True" ]; then
        echo "ESP was enabled but credentials auth or keytab auth was set to true."
        exit 1
    fi

    ### Keytab authentication. Here we write the keytab to disk, either in /etc/krb5.d/krb5.keytab
    ### on in a different location that may have been requested by the user
    if [ "${ESP_KEYTAB_ENABLED}" == "True" ]; then

        #### Bailout if keytab encoded string is empty
        if [ -z "${ESP_B64_KEYTAB// }" ]; then
            echo "No b64 keytab was provided"
            exit 1
        fi

        base64 -d <<< "${ESP_B64_KEYTAB}" > "${ESP_KEYTAB_LOCATION}/${ESP_KEYTAB_NAME}"
        chmod 0600 "${ESP_KEYTAB_LOCATION}/${ESP_KEYTAB_NAME}"
        echo "Keytab created"

        #### Ensure that no ticket init and renewals services will run since keytab is expected
        #### to handle that
        export ENABLE_KRB_TICKET_INIT="False"
        export ENABLE_KRB_TICKET_RENEWAL="False"
    fi

    ### Credentials authenitcation method. This method is second to keytab. That is, if both have
    ### been enabled, then keytab will be used and credentials will be ingored
    if [ "${ESP_CREDENTIALS_ENABLED}" == "True" ] && [ "${ESP_KEYTAB_ENABLED}" != "True" ]; then

        #### Ensure that the ticket init and renewal services will be started
        export ENABLE_KRB_TICKET_INIT="True"
        export ENABLE_KRB_TICKET_RENEWAL="True"

        #### Write credentials to disk, under /etc/lenses.env.
        #### This file should always have 0600
        if ! grep -iq 'ESP_USERNAME' /etc/lenses.env; then
            printf "%q\n" ESP_USERNAME="${ESP_USERNAME}" \
                >> /etc/lenses.env

            echo "Username parsed"
        fi
        if ! grep -iq 'ESP_PASSWORD' /etc/lenses.env; then
            printf "%q\n" ESP_PASSWORD="${ESP_PASSWORD}" \
                >> /etc/lenses.env

            echo "Password parsed"
        fi
    fi

    ### Handle custom jaas. Here we decode the base64 jaas and write it to disk,
    ### under /etc/krb5.d/kafka_client_jaas.conf.
    ### Note: The jaas file can have a keyTab option entry that can point to any
    ###       location that the user could have selected. The user is responsible to also
    ###       add that location along with the correct keytab name by providing
    ###       the following parameters: -L /some/path -N someName
    ###
    if [ "${ESP_JAAS_ENABLED}" == "True" ]; then
        [ -z "${ESP_B64_JAAS// }" ] && {
            echo "No b64 jaas was provided"
            exit 1
        }

        base64 -d <<< "${ESP_B64_JAAS}" > "/etc/krb5.d/kafka_client_jaas.conf"
        chmod 0600 "/etc/krb5.d/kafka_client_jaas.conf"
        echo "Custom Jaas created"
    fi

    ### If the user has a keytab or a custom jaas, then update the JAAS_PATH 
    ### which will be used in LENSES_OPTS
    ### Here we have two cases. The first if case (True) points to the created jaas
    ### The second if case (False) points to the default jaas file provided by Azure HDinsight
    ### which uses a ticketCache
    if [ "${ESP_KEYTAB_ENABLED}" == "True" ] || [ "${ESP_JAAS_ENABLED}" == "True" ]; then
        export JAAS_PATH="/etc/krb5.d/kafka_client_jaas.conf"
    else
        export JAAS_PATH="/usr/hdp/current/kafka-broker/conf/kafka_client_jaas.conf"
    fi

    ### Set LESES_OPTS with the appropriate jaas file.
    ### Warning: We do not write over already existing values.
    ###          If a value (e.g. LENSES_OPTS) has already been set
    ###          by a different process, then that value will be applied
    ###
    if ! grep -iq 'LENSES_OPTS' /etc/lenses.env; then
        echo "LENSES_OPTS=-Djava.security.auth.login.config=${JAAS_PATH}" \
            >> /etc/lenses.env

        echo "Passing lenses opts to env"
    fi
fi

## Do a daemon reload to let systemd know about the services we created earlier
sudo systemctl daemon-reload

## Start Krb5 ticket init and renewal services only when esp is enabled and creds
## have been provided. This option is set during keytab/creds configuration above
if [ "${ESP_ENABLED}" == "True" ] && [ "${ENABLE_KRB_TICKET_INIT}" == "True" ]; then
    if ! command -v krenew >/dev/null 2>&1; then
        apt -y install kstart
    fi

    sudo systemctl start krb-ticket-init.service
    sudo systemctl enable krb-ticket-init.service
    echo "KRB5 ticket init systemd unit started and enabled"

    # sudo systemctl start krb-ticket-renewal.service
    # sudo systemctl enable krb-ticket-renewal.service
    # echo "KRB5 ticket renewal systemd unit started and enabled"

    sleep 2
    if ! systemctl is-active krb-ticket-init.service >/dev/null 2>&1; then
        echo "Ticket init service failed"
        exit 1
    fi
fi

## Finaly restart lenses-io service (incase it was already started) and enable it
sudo systemctl restart lenses-io
sudo systemctl enable lenses-io.service
echo "Lenses systemd unit started and enabled"
