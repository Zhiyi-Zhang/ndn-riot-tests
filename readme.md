NDNoT: 
NLF: NDN Lightweight Forwarding
Security Bootstrapping
Service Discovery
Access Control

TODO List
Interest Parameters: to reduce name length
NFL to maintain a <CK, valid host name> table
Add verify signed interest and interest signing API


Security Bootstrapping
Round trip one:
Device: Interest ->
/ndn/sign-on/hash
Parameter 1: <BK digest>
Parameter 2: <Signature by ECC, BK>
Controller: Data ->
Name: /ndn/sign-on/hash
Content:
Anchor certificate
Token
Key hash (hash two BKs)
Data signed by HMAC

Round trip two:
Device: Interest ->
/<home prefix>/cert/hash
Parameter 1: <BK digest>
Parameter 2: <CK pub key bits> 
Parameter 2: <Signature by HMAC>
Controller: Data ->
Name: /<home prefix>/cert/hash
Content: Issued certificate (Signature by ECC, Anchor’s key)
Data signed by HMAC


Service Discovery (Need more details, e.g., timer, attack defense, etc.)
Main idea: nodes periodically broadcast with its identity (assigned by controller via bootstrap) and available services list appended in the name. Other devices learn identities in the networks and services each identity provide correspondingly.
Periodic Interest notification + Meta Data Query
Round1: broadcast notification interest
Round2: unicast service query with specific service and identity name

Naming Convention:
Round1:
/<home prefix>/SD/<identity>/<SL>/<service name 1>/<service name 2>/…
(e.g., /ucla397/servicediscovery/xpro-TY/servicelist/printer/readNum/light)
Round2: 
		/<home prefix>/<identity>/<service>/<query>/…
(e.g., /ucla397/AC/readTmp/query/v2)

Why we don’t use interest parameters here: 
Since this phase of notification have not data following the interest, using parameters would only increase the overhead.

Security
Round2 is signed by device’s communication key

Access Control (under going)
Main idea: Authentication Server and Producer use classic Diffie Hellman algorithm to generate a shared secret, which will be used to encrypt producer’s data. Authentication Server and Producer also use classic Diffie Hellman to generate a seed. Server uses this seed to encrypt shared secret and distribute it to Consumer. Consumer and Producer use this shared secret to control access. 

Authentication Server - Producer
P: Interest->
<home prefix>/<AC>/<identity>/<AC parameter>/<optional parameter>/<DH bits>/<signature>
Access Control Parameter
Indicate specific command type and type of identity (consumer/producer)

Optional Parameter
Depending on Access Control Parameter (carrying detailed info)

	AS: Data->
DH bits (AS-P)
Signature by anchor key

Authentication Server - Consumer
C: Interest->
<home prefix>/<AC>/<identity>/<AC parameter>/<optional parameter>/<DH bits>/<signature>
AS: Data->
DH bits (AS-C)
Seed (AS-C) encrypted shared secret (AS-P)
Signature by anchor key
 	
Consumer obtain DH bits (AS-C) and derive seed (AS-C) use classic Diffie Hellman, which laterly used for decrypt shared secret (AS-P).

Producer - Consumer
C: Interest->

P: Data->
Shared secret (AS-P) encrypted content
Signature by anchor key
 	
Consumer use shared secret (AS-P) obtained from the last round to decrypt

AC Parameter Convention
Two bytes field (user can extend field with their own preference)
First byte: indicate identity type in *this* Access Control Interest, since in many scenarios, the single identity can both serve as producer and consumer
ACE_CONTROLLER		Controller
ACE_PRODUCER		Producer
ACE_CONSUMER		Consumer
Second byte: indicate access control operation type
ACE_PRODUCER_GLOBAL		Producer
Apply for access control for sender’s identity in whole network
ACE_CONSUMER_GLOBAL		Consumer
Apply for seed of a globally access controlled identity, specific identity name contained in *optional parameter*
User defined msg type

