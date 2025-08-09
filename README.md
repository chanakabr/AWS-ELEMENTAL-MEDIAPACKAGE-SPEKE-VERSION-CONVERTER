# AWS-ELEMENTAL-MEDIAPACKAGE-SPEKE-VERSION-CONVERTER
 This is a sample implementation for AWS Elemental MEdiaPackager V1/V2 with SPEKEv2 Protocol.
 It can be used as a reference.
The license server (ContentKeyServer). supports SPEKEv1 only.
The Overall flow is:
```AWS MP <=(A)=> API GW (Lamba_Proxy) <=(B)=> Lambda <=(C)=> Content Key Server```
The lambda setup has following features.
1. KMS (For storing any Content Key Server Credentials)
2. VPC with static IP (that Content Key Server uses for AllowListing)
3. Lamba function can access teh KMS to set credentials
4. Lambda function will convert SPEKEv2 request to SPEKEv1 and pass to the Key Sever
5. The Lambda will convert the SPEKEv1 response to SPEKEv2 and return to the API GW


