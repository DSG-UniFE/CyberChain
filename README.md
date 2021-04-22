# CyberChain

## Create Fabric Network

First of all you need to create cryptographic material (x509 certs and signing keys) for your various network actors modifying the crypto-config.yaml file and using the cryptogen tool to generate them.
Now you need create the configuration artifacts modifying configtx.yaml file which contains the definitions for the sample network and using the configtxgen tool. In this case, the files that you'll create are:

* orderer genesis block,
* channel configuration transaction,
* five anchor peer transactions (one for each Peer Organization: orgAgent, orgCtrl, orgGw1, orgGw2, orgGw3).

The profiles used are:

* "**OrgsSubChannel1**" to create channel configuration with three organizations (Agent, Controller and Gateway);
* "**OrgsChannelGw**" to create channel configuration with four organizations (Controller and three Gateway);
* "**MultiNodeEtcdRaft**" to create genesis block of network configuration.

*Remember: Pay attention to the “Profiles” section at the bottom of configtx.yaml file.*

After that, you can run the network. You will notice that will be started one peer and one CAs for each organization and 5 Raft orderers (for the quorum). The image used is v2.3.1 for all peers and latest for CAs.

*WARNING: We deployed the peers to three different servers with an orderer on each.*

## Crate channel

To create the channel, we used the CLI fabric-tool (latest version).

For the following CLI commands against peer0.orgGw1.$NETWORK_NAME.com CLI to work, you need to preface four environment variables given below. These informations are essential to indicate to the cli which peer it must connect.
In this case:

```
OrgGw1
- CORE_PEER_MSPCONFIGPATH=$PATH/msp
- CORE_PEER_ADDRESS=peer0.orgGw1.$NETWORK_NAME.com:7051
- CORE_PEER_LOCALMSPID="OrgGw1MSP"
- CORE_PEER_TLS_ROOTCERT_FILE=$PATH/ca.crt
```

Now you can execute the command below to create a channel:

```
peer channel create -o orderer.$NETWORK_NAME.com:7050 -c $CHANNEL_NAME -f $PATH/$CHANNEL.tx --tls --cafile $PATH/tlsca.$NETWORK_NAME.com-cert.pem
```

After that you can join OrgGw1 peer to the channel:

```
peer channel join -b $CHANNEL_NAME.block
```

These operations must be performed for all organizations.

## Anchor peer update

At this point you need to update the anchor peers as follows:

```
peer channel update -o orderer.$NETWORK_NAME.com:7050 -c $CHANNEL_NAME -f $PATH/OrgGw1MSPanchors.tx --tls --cafile $PATH/tlsca.$NETWORK_NAME.com-cert.pem
```

## Install the chaincode

First, you need to install the Go (in this case) chaincode on every peer that will execute and endorse your transactions.
The members of the channel need to agree the chaincode definition that establishes chaincode governance.

You need to package the chaincode before it can be installed on peers.

```
peer lifecycle chaincode package $CHAINCODE.tar.gz --path $PATH/chaincode/$CHAINCODE --lang golang --label $CHAINCODE_1.0
```

After that, you need to provide a chaincode package label as a description of the chaincode. Then you can approve the chaincode definition:

```
peer lifecycle chaincode approveformyorg --channelID $CHANNEL_NAME --name $CHAINCODE --version 1.0 --package-id $CC_PACKAGE_ID --sequence 1 --tls --cafile $PATH/tlsca.$NETWORK_NAME.com-cert.pem
```

Now we provided a **--signature-policy** argument to the command above to set the chaincode endorsement policy. In sub-channel case, the policy will require an endorsement from a peer belonging to 2 out of **OrgGw1, OrgCtrl AND OrgAgent** (i.e. three endorsements).

Since all channel members have approved the definition, you can now commit it to the channel as follows:

```
$peer lifecycle chaincode commit -o orderer.$NETWORK_NAME.com:7050 --channelID $CHANNEL_NAME --name $CHAINCODE --version 1.0 --sequence 1 --tls --cafile "$PATH/tlsca.$NETWORK_NAME.com-cert.pem" --peerAddresses peer0.orgGw1.$NETWORK_NAME.com:7051 --tlsRootCertFiles "$PATH/ca.crt" --peerAddresses peer0.orgCtrl.$NETWORK_NAME.com:10051 --tlsRootCertFiles "$PATH/ca.crt"      --peerAddresses peer0.orgAgent.$NETWORK_NAME.com:11051 --tlsRootCertFiles "$PATH/ca.crt"
```

Now you can invoke the chaincode.

*WARNING: To resolve the logical host names, we configured the /etc/hosts file*
