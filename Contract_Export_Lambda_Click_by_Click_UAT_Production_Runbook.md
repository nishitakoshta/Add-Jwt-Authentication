# Contract Export Lambda – UAT & Production Setup Runbook
## Click-by-click AWS Console instructions based on the DEV implementation

**Audience:** Manager / AWS Administrator / DevOps  
**Purpose:** Repeat the same infrastructure setup completed in DEV for UAT and Production.  
**Access requirement:** The manager/AWS administrator can complete the AWS Console steps using their own authorized AWS login. The developer does not need AnyDesk access to the manager's computer or server for these AWS configuration tasks.

> **Important:** This runbook follows the actual DEV setup and troubleshooting sequence. For UAT and Production, use the environment's own AWS account, region, VPC, subnets, security groups, database endpoint, bucket and role. Do not copy DEV IDs into another environment. Replace all `<PLACEHOLDERS>` before making changes.

---

# 1. What needs to be connected

The worker needs these connections:

1. **Lambda → MySQL:** Lambda connects privately to the environment's database on the MySQL port.
2. **Lambda → S3:** Lambda uploads the generated Excel file to the environment's S3 bucket.
3. **Lambda → IAM execution role:** The role authorizes Lambda to write objects to the export folder.
4. **Lambda subnet → S3 Gateway VPC endpoint:** The subnet's route table routes S3 traffic through the Gateway endpoint.
5. **Backend → Lambda/job flow:** The application creates the export job and triggers the worker using the implementation already present in the backend.

```text
Backend / API
     |
     | Creates export job
     v
 MySQL Database <--------------------------+
     ^                                     |
     | Lambda reads/updates job + data     |
     |                                     |
 AWS Lambda                                |
     |                                     |
     | Generates Excel                     |
     v                                     |
 Amazon S3                                 |
     ^                                     |
     |                                     |
 S3 Gateway VPC Endpoint                   |
     ^                                     |
     | Route table associated with         |
     | Lambda subnet                       |
     +-------------------------------------+

Lambda execution role authorizes S3 upload.
```

---

# 2. Before starting – collect environment details

The manager/AWS administrator should collect these details for **UAT** and again for **Production**. They can be found in the AWS Console as described in the relevant sections below.

| Required value | UAT | Production |
|---|---|---|
| AWS account ID | `<UAT_ACCOUNT_ID>` | `<PROD_ACCOUNT_ID>` |
| AWS Region | `<UAT_REGION>` | `<PROD_REGION>` |
| VPC ID | `<UAT_VPC_ID>` | `<PROD_VPC_ID>` |
| Lambda function name | `<UAT_LAMBDA_NAME>` | `<PROD_LAMBDA_NAME>` |
| Lambda subnet ID(s) | `<UAT_LAMBDA_SUBNET_IDS>` | `<PROD_LAMBDA_SUBNET_IDS>` |
| Lambda security group ID | `<UAT_LAMBDA_SG_ID>` | `<PROD_LAMBDA_SG_ID>` |
| Database private endpoint/IP | `<UAT_DB_HOST>` | `<PROD_DB_HOST>` |
| Database port | `<DB_PORT>` | `<DB_PORT>` |
| Database/schema name | `<UAT_DB_NAME>` | `<PROD_DB_NAME>` |
| S3 bucket | `<UAT_BUCKET>` | `<PROD_BUCKET>` |
| Lambda execution role | `<UAT_LAMBDA_ROLE>` | `<PROD_LAMBDA_ROLE>` |
| Route table(s) for Lambda subnet(s) | `<UAT_ROUTE_TABLE_IDS>` | `<PROD_ROUTE_TABLE_IDS>` |

**Do not put database passwords, access keys or secret values in this runbook.**

---

# 3. Step 1 – Identify the Lambda function and its VPC settings

### Where to click

1. Sign in to the correct AWS account (first UAT, then Production).
2. In the AWS Console search bar, type **Lambda** and open the Lambda service.
3. In the left menu, click **Functions**.
4. Search for the environment's contract-export function.
   - If it already exists, click its function name.
   - If it does not exist, the administrator should create it using the approved deployment process and the handler/runtime details supplied by the development team.
5. Open the **Configuration** tab.
6. In the left-side Configuration menu, click **VPC**.
7. Note the following:
   - VPC
   - Subnet(s)
   - Security group(s)

### What to configure

The Lambda must be attached to the VPC that can reach the environment's private database.

| Setting | Value to use |
|---|---|
| VPC | `<ENVIRONMENT_VPC_ID>` |
| Subnet(s) | Private subnet(s) with database connectivity |
| Security group | Dedicated Lambda security group, `<ENV_LAMBDA_SG_ID>` |

If changes are required:

1. On the Lambda **Configuration → VPC** page, click **Edit**.
2. Select the correct VPC.
3. Select the required private subnet(s).
4. Select the Lambda security group.
5. Click **Save**.
6. Wait for the VPC update to finish before continuing.

**Note:** Use the actual subnets and security groups approved for the environment. Do not select a subnet only because it was used in DEV.

---

# 4. Step 2 – Allow Lambda to connect to MySQL

This is configured on the security group attached to the database server (EC2 or RDS).

## 4.1 Find the database security group

### If MySQL is hosted on EC2

1. Open **EC2** from the AWS Console search.
2. In the left menu, click **Instances**.
3. Search for and select the UAT/Production database EC2 instance.
4. Open the **Security** tab in the lower details panel.
5. Under **Security groups**, click the security group ID.
6. The EC2 Security Group page opens.

### If MySQL is hosted on RDS

1. Open **RDS**.
2. Click **Databases**.
3. Select the database instance.
4. Open its **Connectivity & security** section.
5. Under **VPC security groups**, click the relevant security group.

## 4.2 Add the inbound MySQL rule

1. On the database security group page, open **Inbound rules**.
2. Click **Edit inbound rules**.
3. Click **Add rule**.
4. Set:

| Field | Value |
|---|---|
| Type | MySQL/Aurora |
| Protocol | TCP |
| Port range | `3306` (or the actual DB port) |
| Source | Lambda security group ID, `<ENV_LAMBDA_SG_ID>` |

5. Add a description such as `Allow contract export Lambda to access MySQL`.
6. Click **Save rules**.

**Security requirement:** Do not use `0.0.0.0/0` as the database rule source. The source should be the Lambda security group (or another specifically approved private source).

## 4.3 Check Lambda security group outbound rules

1. Open **EC2 → Network & Security → Security Groups**.
2. Search for the Lambda security group ID.
3. Select it and open **Outbound rules**.
4. Confirm outbound traffic permits the database port to the database security group/private address and permits the required S3 route.
5. If outbound rules are restricted, ask the network administrator to add only the approved rules.

A security group is stateful, so response traffic for an allowed connection is automatically permitted.

---

# 5. Step 3 – Confirm MySQL is listening on the private network

This step is for the server/DB administrator. It is not an AWS Console-only change.

For a MySQL database hosted on EC2:

1. Connect to the database EC2 using the organization's approved SSH/session method.
2. Check the MySQL configuration file used by that server. On the DEV machine, the file was:

   ```text
   /etc/mysql/mysql.conf.d/mysqld.cnf
   ```

3. Confirm MySQL listens on the private interface reachable by Lambda, not only on `127.0.0.1`.
4. The DEV setup used both loopback and the EC2 private IP in the bind address. For UAT/Production, use the correct private IP/interface for that environment.

Example format only:

```ini
bind-address = 127.0.0.1,<DATABASE_EC2_PRIVATE_IP>
```

5. Back up the configuration file before editing.
6. If a change is needed, have the DBA/server administrator apply it during an approved change window and restart MySQL.
7. Verify the MySQL service is running and listening on the intended private interface and port.

**Do not paste the DEV private IP into UAT/Production.** If the database is RDS, do not attempt to edit MySQL bind-address; RDS networking is controlled through the RDS/VPC configuration.

---

# 6. Step 4 – Create the dedicated MySQL worker user

This step is performed by the DBA/database administrator, using the target environment's database credentials.

The DEV worker used a dedicated account named `contract_export_worker`. The UAT/Production DBA can use the same naming convention or the organization's approved account name.

### 6.1 Confirm the Lambda source range/host

The DBA must confirm which private source address/range the Lambda connection will use. For Lambda, this is associated with its VPC network interfaces/subnets. The host pattern must match the actual source address observed by MySQL.

Do not copy the DEV host pattern into another environment.

### 6.2 Create/grant the account

Example only – replace all placeholders and follow the organization's database access policy:

```sql
CREATE USER '<WORKER_DB_USER>'@'<LAMBDA_SOURCE_HOST_PATTERN>'
IDENTIFIED BY '<STRONG_UNIQUE_PASSWORD>';

GRANT SELECT, INSERT, UPDATE, DELETE
ON <DATABASE_NAME>.*
TO '<WORKER_DB_USER>'@'<LAMBDA_SOURCE_HOST_PATTERN>';

FLUSH PRIVILEGES;
```

If the account already exists, the DBA should verify its host pattern and privileges instead of creating a duplicate.

### 6.3 Important database notes

- Use a dedicated worker account, not `root` or an application DBA account.
- Grant access only to the database/schema required by the worker.
- The example privileges are the privileges used/identified for the DEV worker setup. The DBA and developer should verify whether the deployed code requires any additional operation.
- Share the password through an approved secrets-management channel only.

---

# 7. Step 5 – Create the S3 bucket or confirm the existing bucket

The administrator should use the approved bucket for each environment. UAT and Production may use separate buckets or separate approved prefixes, according to the organization's storage policy.

### Where to click

1. Open **S3** from the AWS Console search.
2. Click **Buckets**.
3. Search for the approved UAT bucket.
   - If it exists, click the bucket name.
   - If it does not exist, click **Create bucket** and follow the organization's naming, region and security standards.
4. Open the bucket and confirm the export folder/prefix to be used.

Recommended object prefix:

```text
contract-exports/
```

S3 folders are prefixes created by object keys; an empty folder does not have to be created manually if the application writes objects under that prefix.

### Bucket security checks

- Keep **Block Public Access** enabled unless a formally approved exception exists.
- Use the organization's required encryption settings.
- Confirm lifecycle/retention requirements for generated exports.
- Do not make the bucket or objects public to make downloads work.
- Confirm the bucket's region and use that region in the Lambda configuration.

---

# 8. Step 6 – Create the S3 Gateway VPC endpoint

This is the network configuration that resolved the S3 connection timeout in DEV.

### 8.1 Open the VPC Endpoints page

1. In the AWS Console search bar, type **VPC** and open the VPC service.
2. In the left menu, under **Virtual private cloud**, click **Endpoints**.
3. Click **Create endpoint**.

### 8.2 Enter endpoint details

Fill in the fields:

| Field | What to select |
|---|---|
| Name tag | `<ENV>-contract-export-s3-endpoint` |
| Service category | AWS services |
| Services search | `com.amazonaws.<AWS_REGION>.s3` |
| Service | S3 service for the same AWS Region |
| VPC | `<ENVIRONMENT_VPC_ID>` |
| Endpoint type | Gateway |

Select the S3 service for the same region used by the Lambda and bucket.

### 8.3 Select the route table(s)

1. On the endpoint creation page, locate the **Route tables** section.
2. Select the route table associated with the subnet(s) selected for the Lambda function.
3. If Lambda uses more than one subnet, identify and select the route table associated with each relevant subnet.
4. Do not select unrelated route tables.
5. Review the endpoint policy. Use the approved policy that permits the required access to the target bucket/prefix and does not deny the upload.
6. Click **Create endpoint**.

### 8.4 Wait for endpoint status

1. Return to **VPC → Endpoints**.
2. Search for the endpoint name created above.
3. Wait until **Status** shows **Available**.
4. Note the endpoint ID (`vpce-...`) for the environment record.

**Important:** A Gateway endpoint does not have a security group. Its route-table association is what directs S3 traffic through the endpoint.

---

# 9. Step 7 – Verify the S3 route in the route table

This is a separate verification. Creating the endpoint is not enough; the correct Lambda subnet route table must be associated with it.

### Where to click

1. Open **VPC → Route tables**.
2. Search for and select the route table associated with the Lambda subnet.
3. Open the **Routes** tab.
4. Click **Refresh**.
5. Find the route whose destination is an S3 prefix list (`pl-...`).
6. Confirm its target is the S3 Gateway endpoint created in Step 6 (`vpce-...`).
7. Confirm the route status is **Active**.

Expected pattern:

| Destination | Target | Status |
|---|---|---|
| S3 prefix list (`pl-...`) | S3 Gateway endpoint (`vpce-...`) | Active |
| VPC CIDR | `local` | Active |
| Other existing routes | Existing target | As designed |

If the S3 prefix-list route is missing:
- Return to **VPC → Endpoints**.
- Select the S3 Gateway endpoint.
- Open its **Route tables** association/edit option.
- Associate the correct route table used by the Lambda subnet.
- Save, then return to the route table and refresh.

Do not remove or modify unrelated existing routes.

---

# 10. Step 8 – Configure the Lambda execution role and S3 permission

The DEV CloudWatch test first showed an S3 timeout. After the S3 Gateway endpoint was linked, the error changed to HTTP 403 `AccessDenied`, specifically stating that the Lambda role did not have `s3:PutObject`. This is why the role permission must also be configured.

## 10.1 Find the role attached to Lambda

1. Open **Lambda → Functions**.
2. Click the target environment's contract-export function.
3. Open **Configuration**.
4. Click **Permissions** in the left-side menu.
5. Under **Execution role**, click the role name. This opens the role in IAM.
6. Confirm this is the role actually attached to the target Lambda.

## 10.2 Create an inline policy

1. On the IAM role page, open the **Permissions** tab.
2. Click **Add permissions**.
3. Select **Create inline policy**.
4. Select the **JSON** tab.
5. Paste the policy below after replacing `<BUCKET_NAME>` with the correct environment bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowContractExportUpload",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::<BUCKET_NAME>/contract-exports/*"
    }
  ]
}
```

6. Click **Next**.
7. Enter a policy name, for example:

   ```text
   <ENV>-ContractExportS3UploadAccess
   ```

8. Click **Create policy** / **Add permissions** (button label may vary).
9. Return to the role's **Permissions** tab.
10. Confirm the new policy appears in the permission list.

### Permission scope

This policy allows Lambda to upload objects only under:

```text
s3://<BUCKET_NAME>/contract-exports/
```

Do not attach `AmazonS3FullAccess` for this upload requirement.

If the actual code also reads, lists, deletes, or performs multipart operations on S3, the administrator and developer must review those operations and add only the required permissions. Do not assume `PutObject` authorizes every S3 operation.

Also check that the S3 bucket policy and VPC endpoint policy do not contain an explicit Deny for the Lambda role, bucket or prefix.

---

# 11. Step 9 – Configure Lambda environment variables

### Where to click

1. Open **Lambda → Functions**.
2. Click the target environment's contract-export function.
3. Open **Configuration**.
4. In the left-side menu, click **Environment variables**.
5. Click **Edit**.
6. Add/update the values expected by the application's config module.
7. Click **Save**.

### Values to configure

| Setting / variable | Value |
|---|---|
| `DB_HOST` | Private database endpoint/IP for this environment |
| `DB_PORT` | Database port (DEV used `3306`) |
| Database name variable | Target environment database/schema |
| Database user variable | Dedicated worker DB account |
| Database password variable | Secret for the worker account |
| `AWS_REGION` | Target AWS Region |
| `AWS_BUCKET` | Target environment S3 bucket |

**Important:** The exact environment variable names for database name, username and password must be taken from the deployed project's `config/config.js` / `config/nodeConfig.js`. Do not invent new names. Keep the key names identical to what the code reads.

For credentials:
- Use AWS Secrets Manager if that is the organization's standard.
- If the code currently reads a password from Lambda environment variables, enter it through the protected console workflow and restrict who can view/update the configuration.
- Never put actual passwords in this runbook, email or chat.

---

# 12. Step 10 – Configure Lambda runtime, handler, memory and timeout

### Where to click

1. Open **Lambda → Functions → target contract-export function**.
2. Open the **Code** tab.
3. Confirm the runtime and handler match the deployment package.
4. To check runtime: open **Configuration → General configuration**.
5. Click **Edit** to change memory or timeout if required.
6. Save the approved settings.

Application package handler used in DEV:

```text
lambda/contractExportHandler.handler
```

Runtime used in DEV:

```text
Node.js 22.x
```

The DEV function was observed with:
- Memory: `1024 MB`
- Timeout: `5 minutes`

These are reference values only. The administrator should confirm UAT/Production values with the development and database teams. Do not increase concurrency without reviewing MySQL connection capacity and job locking.

---

# 13. Step 11 – Deploy the Lambda ZIP package

The developer prepares and supplies the approved deployment ZIP. The manager/DevOps administrator uploads it to the correct environment function.

## 13.1 Developer prepares the package

The package must contain the handler and required runtime files, including the services, models, config, dependencies and Excel template.

Example package structure:

```text
lambda-package/
  config/
  excel_format_data/
  lambda/
    contractExportHandler.js
  models/
  services/
    contractExportJobService.js
    contractExportService.js
  utils/
    contractExportCache.js
    logger.js
    s3Upload.js
  package.json
  package-lock.json
```

If the project uses AWS SAM, the build command from the repository root is:

```bash
sam build --clean
```

The ZIP is created from the built Lambda artifact directory, for example:

```bash
cd .aws-sam/build/ContractExportFunction
zip -qr /tmp/contract-export-worker.zip .
```

The developer should provide the ZIP through the approved artifact-sharing/release process, with its version/commit noted.

## 13.2 Manager/DevOps uploads the ZIP

1. Open **AWS Console → Lambda → Functions**.
2. Select the UAT function (do UAT first).
3. Open the **Code** tab.
4. Click **Upload from**.
5. Select **.zip file**.
6. Choose the ZIP artifact supplied by the developer.
7. Click **Save** / **Deploy**.
8. Wait until the code update completes.
9. Confirm the handler, runtime, role, VPC and environment variables are still correct.

Repeat the same steps for Production only after UAT validation and Production approval.

**Deployment ownership note:** If the Lambda is managed by CloudFormation/SAM/Terraform or a CI/CD pipeline, deploy through that approved system instead of manually uploading in the Console. Do not create a new CloudFormation stack just to upload code to an existing manually created Lambda.

---

# 14. Step 12 – Test the export in UAT

After all previous steps are completed:

1. Ask the developer/application tester to trigger a **fresh export request** from the UAT application/API.
2. Open **Lambda → Functions → UAT contract-export function**.
3. Click **Monitor**.
4. Click **View CloudWatch logs**.
5. Open the newest log stream/invocation.
6. Check the logs for the worker stages.

Expected success sequence (actual log wording may differ):

```text
Export job claimed / processing
Workbook generation completed
S3 upload started
S3 upload completed
Contract export job completed
```

7. Open **S3 → Buckets → UAT bucket**.
8. Open the `contract-exports/` prefix.
9. Confirm the generated `.xlsx` object exists.
10. Ask the application tester to verify that the export can be downloaded through the existing application flow.
11. Confirm the export job/cache record has the expected completed status.

If a previous job reached its terminal failed state after exhausting retries, do not assume it will run again. Check the job status and create a fresh export request if required by the application's retry behavior.

---

# 15. Step 13 – Promote to Production

Do not start Production setup by copying DEV IDs. Repeat the same steps using Production resources.

Recommended sequence:

1. UAT setup completed.
2. UAT export test passed.
3. UAT S3 object and application download verified.
4. UAT sign-off received.
5. Production resource IDs, database endpoint, bucket and role confirmed.
6. Production networking and security configuration reviewed.
7. Production S3 endpoint and route table verified.
8. Production IAM policy reviewed and approved.
9. Production secrets/environment variables configured.
10. Approved artifact deployed to Production.
11. Controlled Production smoke test performed.
12. Production object/download verified.
13. Deployment evidence and rollback artifact recorded.

---

# 16. Troubleshooting – use the exact error to identify the missing setup

| CloudWatch error | Meaning | What to check |
|---|---|---|
| `ETIMEDOUT` to S3 IP on TCP 443 | Lambda cannot establish the S3 network connection. | S3 Gateway endpoint is Available; correct route table is associated; S3 prefix-list route targets the endpoint. |
| `403 AccessDenied` / `s3:PutObject` not authorized | Network path works, but the Lambda role does not have upload permission. | IAM execution role has `s3:PutObject` scoped to the correct bucket/prefix; check bucket and endpoint policies for explicit Deny. |
| MySQL `ETIMEDOUT` / connection refused | Lambda cannot reach the database listener. | DB endpoint/port, database security group inbound rule, Lambda VPC/subnet/SG, route and MySQL listener. |
| MySQL access denied | Credentials or MySQL host grant do not match. | Worker username/password, host pattern and schema privileges. |
| Lambda timeout | Work takes longer than configured timeout. | Workbook generation, DB queries, S3 upload and Lambda timeout/memory. |
| Job failed or remains processing | Worker exception, retry limit or job-state handling. | First error in CloudWatch and job attempts/status in MySQL. |

### Important DEV troubleshooting sequence (reference)

During the DEV setup:
1. The first S3 upload attempt failed with `ETIMEDOUT` to S3 IP addresses on TCP `443`.
2. An S3 Gateway VPC endpoint was created and associated with the Lambda subnet's route table.
3. The route table showed an Active S3 prefix-list route targeting the Gateway endpoint.
4. The next upload attempt reached S3 but failed with HTTP `403 AccessDenied`.
5. CloudWatch explicitly reported that the Lambda execution role lacked `s3:PutObject`.
6. A scoped inline IAM policy was then identified as the required permission.

This demonstrates that **network routing and IAM authorization are two separate requirements**. Both must be configured.

---

# 17. Performance reference from DEV

One observed DEV Lambda invocation reported:

| Metric | Observed value |
|---|---:|
| Duration | `40,590.91 ms` (~40.59 seconds) |
| Billed duration | `41,773 ms` (~41.77 seconds) |
| Init duration | `1,181.53 ms` (~1.18 seconds) |
| Memory size | `1,024 MB` |
| Max memory used | `592 MB` |

These figures are from one DEV invocation only. UAT/Production should be tested with representative export sizes before deciding memory, timeout or concurrency.

---

# 18. Final manager checklist

## UAT

- [ ] Lambda function selected/created.
- [ ] Lambda VPC, private subnet(s) and security group configured.
- [ ] Database security group allows the Lambda security group on the DB port.
- [ ] MySQL is listening on the private interface (EC2-hosted MySQL only).
- [ ] Dedicated worker database user and required privileges created.
- [ ] UAT S3 bucket and `contract-exports/` prefix confirmed.
- [ ] S3 Gateway endpoint created for the correct region and VPC.
- [ ] Endpoint associated with the route table(s) used by Lambda subnet(s).
- [ ] S3 prefix-list route is Active and points to the endpoint.
- [ ] Lambda execution role identified.
- [ ] Scoped `s3:PutObject` permission added to the correct role.
- [ ] Bucket/endpoint policies checked for explicit Deny.
- [ ] Lambda environment variables/secrets configured.
- [ ] Correct runtime, handler, memory and timeout confirmed.
- [ ] Approved Lambda ZIP deployed.
- [ ] Fresh UAT export succeeds.
- [ ] S3 object exists and application download works.

## Production

- [ ] Production-specific values and resources independently confirmed.
- [ ] All UAT setup steps repeated with Production resources.
- [ ] Production IAM and database privileges reviewed.
- [ ] Production secrets stored securely.
- [ ] Production artifact and release approved.
- [ ] Production smoke test succeeds.
- [ ] S3 object and application download verified.
- [ ] Rollback artifact and operational owner recorded.

---

## 19. What the developer needs to provide (no AnyDesk required)

The developer can provide these items through the approved repository/release process:

1. Lambda deployment ZIP for the approved release.
2. Handler name and supported Node.js runtime.
3. Required environment-variable **names** and expected purpose (not secret values).
4. Database name/schema and minimum required worker privileges.
5. S3 bucket/prefix requirement.
6. Lambda-to-DB and Lambda-to-S3 connectivity requirements.
7. A test request/use case and expected success behavior.
8. Support during UAT/Production validation using CloudWatch log references or screenshots shared by the administrator.

The manager/AWS administrator performs the console configuration with their own authorized AWS account. The developer does not need to remote-control the manager's computer or receive the manager's AWS credentials.

*End of runbook.*
