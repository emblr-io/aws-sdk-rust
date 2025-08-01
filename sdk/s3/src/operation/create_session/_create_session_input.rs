// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateSessionInput {
    /// <p>Specifies the mode of the session that will be created, either <code>ReadWrite</code> or <code>ReadOnly</code>. By default, a <code>ReadWrite</code> session is created. A <code>ReadWrite</code> session is capable of executing all the Zonal endpoint API operations on a directory bucket. A <code>ReadOnly</code> session is constrained to execute the following Zonal endpoint API operations: <code>GetObject</code>, <code>HeadObject</code>, <code>ListObjectsV2</code>, <code>GetObjectAttributes</code>, <code>ListParts</code>, and <code>ListMultipartUploads</code>.</p>
    pub session_mode: ::std::option::Option<crate::types::SessionMode>,
    /// <p>The name of the bucket that you create a session for.</p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>The server-side encryption algorithm to use when you store objects in the directory bucket.</p>
    /// <p>For directory buckets, there are only two supported options for server-side encryption: server-side encryption with Amazon S3 managed keys (SSE-S3) (<code>AES256</code>) and server-side encryption with KMS keys (SSE-KMS) (<code>aws:kms</code>). By default, Amazon S3 encrypts data with SSE-S3. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html">Protecting data with server-side encryption</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>S3 access points for Amazon FSx </b> - When accessing data stored in Amazon FSx file systems using S3 access points, the only valid server side encryption option is <code>aws:fsx</code>. All Amazon FSx file systems have encryption configured by default and are encrypted at rest. Data is automatically encrypted before being written to the file system, and automatically decrypted as it is read. These processes are handled transparently by Amazon FSx.</p>
    pub server_side_encryption: ::std::option::Option<crate::types::ServerSideEncryption>,
    /// <p>If you specify <code>x-amz-server-side-encryption</code> with <code>aws:kms</code>, you must specify the <code> x-amz-server-side-encryption-aws-kms-key-id</code> header with the ID (Key ID or Key ARN) of the KMS symmetric encryption customer managed key to use. Otherwise, you get an HTTP <code>400 Bad Request</code> error. Only use the key ID or key ARN. The key alias format of the KMS key isn't supported. Also, if the KMS key doesn't exist in the same account that't issuing the command, you must use the full Key ARN not the Key ID.</p>
    /// <p>Your SSE-KMS configuration can only support 1 <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk">customer managed key</a> per directory bucket's lifetime. The <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-cmk">Amazon Web Services managed key</a> (<code>aws/s3</code>) isn't supported.</p>
    pub ssekms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the Amazon Web Services KMS Encryption Context as an additional encryption context to use for object encryption. The value of this header is a Base64 encoded string of a UTF-8 encoded JSON, which contains the encryption context as key-value pairs. This value is stored as object metadata and automatically gets passed on to Amazon Web Services KMS for future <code>GetObject</code> operations on this object.</p>
    /// <p><b>General purpose buckets</b> - This value must be explicitly added during <code>CopyObject</code> operations if you want an additional encryption context for your object. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html#encryption-context">Encryption context</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>Directory buckets</b> - You can optionally provide an explicit encryption context value. The value must match the default encryption context - the bucket Amazon Resource Name (ARN). An additional encryption context value is not supported.</p>
    pub ssekms_encryption_context: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether Amazon S3 should use an S3 Bucket Key for object encryption with server-side encryption using KMS keys (SSE-KMS).</p>
    /// <p>S3 Bucket Keys are always enabled for <code>GET</code> and <code>PUT</code> operations in a directory bucket and can’t be disabled. S3 Bucket Keys aren't supported, when you copy SSE-KMS encrypted objects from general purpose buckets to directory buckets, from directory buckets to general purpose buckets, or between directory buckets, through <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html">CopyObject</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html">UploadPartCopy</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-objects-Batch-Ops">the Copy operation in Batch Operations</a>, or <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-import-job">the import jobs</a>. In this case, Amazon S3 makes a call to KMS every time a copy request is made for a KMS-encrypted object.</p>
    pub bucket_key_enabled: ::std::option::Option<bool>,
}
impl CreateSessionInput {
    /// <p>Specifies the mode of the session that will be created, either <code>ReadWrite</code> or <code>ReadOnly</code>. By default, a <code>ReadWrite</code> session is created. A <code>ReadWrite</code> session is capable of executing all the Zonal endpoint API operations on a directory bucket. A <code>ReadOnly</code> session is constrained to execute the following Zonal endpoint API operations: <code>GetObject</code>, <code>HeadObject</code>, <code>ListObjectsV2</code>, <code>GetObjectAttributes</code>, <code>ListParts</code>, and <code>ListMultipartUploads</code>.</p>
    pub fn session_mode(&self) -> ::std::option::Option<&crate::types::SessionMode> {
        self.session_mode.as_ref()
    }
    /// <p>The name of the bucket that you create a session for.</p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>The server-side encryption algorithm to use when you store objects in the directory bucket.</p>
    /// <p>For directory buckets, there are only two supported options for server-side encryption: server-side encryption with Amazon S3 managed keys (SSE-S3) (<code>AES256</code>) and server-side encryption with KMS keys (SSE-KMS) (<code>aws:kms</code>). By default, Amazon S3 encrypts data with SSE-S3. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html">Protecting data with server-side encryption</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>S3 access points for Amazon FSx </b> - When accessing data stored in Amazon FSx file systems using S3 access points, the only valid server side encryption option is <code>aws:fsx</code>. All Amazon FSx file systems have encryption configured by default and are encrypted at rest. Data is automatically encrypted before being written to the file system, and automatically decrypted as it is read. These processes are handled transparently by Amazon FSx.</p>
    pub fn server_side_encryption(&self) -> ::std::option::Option<&crate::types::ServerSideEncryption> {
        self.server_side_encryption.as_ref()
    }
    /// <p>If you specify <code>x-amz-server-side-encryption</code> with <code>aws:kms</code>, you must specify the <code> x-amz-server-side-encryption-aws-kms-key-id</code> header with the ID (Key ID or Key ARN) of the KMS symmetric encryption customer managed key to use. Otherwise, you get an HTTP <code>400 Bad Request</code> error. Only use the key ID or key ARN. The key alias format of the KMS key isn't supported. Also, if the KMS key doesn't exist in the same account that't issuing the command, you must use the full Key ARN not the Key ID.</p>
    /// <p>Your SSE-KMS configuration can only support 1 <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk">customer managed key</a> per directory bucket's lifetime. The <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-cmk">Amazon Web Services managed key</a> (<code>aws/s3</code>) isn't supported.</p>
    pub fn ssekms_key_id(&self) -> ::std::option::Option<&str> {
        self.ssekms_key_id.as_deref()
    }
    /// <p>Specifies the Amazon Web Services KMS Encryption Context as an additional encryption context to use for object encryption. The value of this header is a Base64 encoded string of a UTF-8 encoded JSON, which contains the encryption context as key-value pairs. This value is stored as object metadata and automatically gets passed on to Amazon Web Services KMS for future <code>GetObject</code> operations on this object.</p>
    /// <p><b>General purpose buckets</b> - This value must be explicitly added during <code>CopyObject</code> operations if you want an additional encryption context for your object. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html#encryption-context">Encryption context</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>Directory buckets</b> - You can optionally provide an explicit encryption context value. The value must match the default encryption context - the bucket Amazon Resource Name (ARN). An additional encryption context value is not supported.</p>
    pub fn ssekms_encryption_context(&self) -> ::std::option::Option<&str> {
        self.ssekms_encryption_context.as_deref()
    }
    /// <p>Specifies whether Amazon S3 should use an S3 Bucket Key for object encryption with server-side encryption using KMS keys (SSE-KMS).</p>
    /// <p>S3 Bucket Keys are always enabled for <code>GET</code> and <code>PUT</code> operations in a directory bucket and can’t be disabled. S3 Bucket Keys aren't supported, when you copy SSE-KMS encrypted objects from general purpose buckets to directory buckets, from directory buckets to general purpose buckets, or between directory buckets, through <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html">CopyObject</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html">UploadPartCopy</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-objects-Batch-Ops">the Copy operation in Batch Operations</a>, or <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-import-job">the import jobs</a>. In this case, Amazon S3 makes a call to KMS every time a copy request is made for a KMS-encrypted object.</p>
    pub fn bucket_key_enabled(&self) -> ::std::option::Option<bool> {
        self.bucket_key_enabled
    }
}
impl ::std::fmt::Debug for CreateSessionInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateSessionInput");
        formatter.field("session_mode", &self.session_mode);
        formatter.field("bucket", &self.bucket);
        formatter.field("server_side_encryption", &self.server_side_encryption);
        formatter.field("ssekms_key_id", &"*** Sensitive Data Redacted ***");
        formatter.field("ssekms_encryption_context", &"*** Sensitive Data Redacted ***");
        formatter.field("bucket_key_enabled", &self.bucket_key_enabled);
        formatter.finish()
    }
}
impl CreateSessionInput {
    /// Creates a new builder-style object to manufacture [`CreateSessionInput`](crate::operation::create_session::CreateSessionInput).
    pub fn builder() -> crate::operation::create_session::builders::CreateSessionInputBuilder {
        crate::operation::create_session::builders::CreateSessionInputBuilder::default()
    }
}

/// A builder for [`CreateSessionInput`](crate::operation::create_session::CreateSessionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateSessionInputBuilder {
    pub(crate) session_mode: ::std::option::Option<crate::types::SessionMode>,
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) server_side_encryption: ::std::option::Option<crate::types::ServerSideEncryption>,
    pub(crate) ssekms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) ssekms_encryption_context: ::std::option::Option<::std::string::String>,
    pub(crate) bucket_key_enabled: ::std::option::Option<bool>,
}
impl CreateSessionInputBuilder {
    /// <p>Specifies the mode of the session that will be created, either <code>ReadWrite</code> or <code>ReadOnly</code>. By default, a <code>ReadWrite</code> session is created. A <code>ReadWrite</code> session is capable of executing all the Zonal endpoint API operations on a directory bucket. A <code>ReadOnly</code> session is constrained to execute the following Zonal endpoint API operations: <code>GetObject</code>, <code>HeadObject</code>, <code>ListObjectsV2</code>, <code>GetObjectAttributes</code>, <code>ListParts</code>, and <code>ListMultipartUploads</code>.</p>
    pub fn session_mode(mut self, input: crate::types::SessionMode) -> Self {
        self.session_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the mode of the session that will be created, either <code>ReadWrite</code> or <code>ReadOnly</code>. By default, a <code>ReadWrite</code> session is created. A <code>ReadWrite</code> session is capable of executing all the Zonal endpoint API operations on a directory bucket. A <code>ReadOnly</code> session is constrained to execute the following Zonal endpoint API operations: <code>GetObject</code>, <code>HeadObject</code>, <code>ListObjectsV2</code>, <code>GetObjectAttributes</code>, <code>ListParts</code>, and <code>ListMultipartUploads</code>.</p>
    pub fn set_session_mode(mut self, input: ::std::option::Option<crate::types::SessionMode>) -> Self {
        self.session_mode = input;
        self
    }
    /// <p>Specifies the mode of the session that will be created, either <code>ReadWrite</code> or <code>ReadOnly</code>. By default, a <code>ReadWrite</code> session is created. A <code>ReadWrite</code> session is capable of executing all the Zonal endpoint API operations on a directory bucket. A <code>ReadOnly</code> session is constrained to execute the following Zonal endpoint API operations: <code>GetObject</code>, <code>HeadObject</code>, <code>ListObjectsV2</code>, <code>GetObjectAttributes</code>, <code>ListParts</code>, and <code>ListMultipartUploads</code>.</p>
    pub fn get_session_mode(&self) -> &::std::option::Option<crate::types::SessionMode> {
        &self.session_mode
    }
    /// <p>The name of the bucket that you create a session for.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the bucket that you create a session for.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of the bucket that you create a session for.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The server-side encryption algorithm to use when you store objects in the directory bucket.</p>
    /// <p>For directory buckets, there are only two supported options for server-side encryption: server-side encryption with Amazon S3 managed keys (SSE-S3) (<code>AES256</code>) and server-side encryption with KMS keys (SSE-KMS) (<code>aws:kms</code>). By default, Amazon S3 encrypts data with SSE-S3. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html">Protecting data with server-side encryption</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>S3 access points for Amazon FSx </b> - When accessing data stored in Amazon FSx file systems using S3 access points, the only valid server side encryption option is <code>aws:fsx</code>. All Amazon FSx file systems have encryption configured by default and are encrypted at rest. Data is automatically encrypted before being written to the file system, and automatically decrypted as it is read. These processes are handled transparently by Amazon FSx.</p>
    pub fn server_side_encryption(mut self, input: crate::types::ServerSideEncryption) -> Self {
        self.server_side_encryption = ::std::option::Option::Some(input);
        self
    }
    /// <p>The server-side encryption algorithm to use when you store objects in the directory bucket.</p>
    /// <p>For directory buckets, there are only two supported options for server-side encryption: server-side encryption with Amazon S3 managed keys (SSE-S3) (<code>AES256</code>) and server-side encryption with KMS keys (SSE-KMS) (<code>aws:kms</code>). By default, Amazon S3 encrypts data with SSE-S3. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html">Protecting data with server-side encryption</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>S3 access points for Amazon FSx </b> - When accessing data stored in Amazon FSx file systems using S3 access points, the only valid server side encryption option is <code>aws:fsx</code>. All Amazon FSx file systems have encryption configured by default and are encrypted at rest. Data is automatically encrypted before being written to the file system, and automatically decrypted as it is read. These processes are handled transparently by Amazon FSx.</p>
    pub fn set_server_side_encryption(mut self, input: ::std::option::Option<crate::types::ServerSideEncryption>) -> Self {
        self.server_side_encryption = input;
        self
    }
    /// <p>The server-side encryption algorithm to use when you store objects in the directory bucket.</p>
    /// <p>For directory buckets, there are only two supported options for server-side encryption: server-side encryption with Amazon S3 managed keys (SSE-S3) (<code>AES256</code>) and server-side encryption with KMS keys (SSE-KMS) (<code>aws:kms</code>). By default, Amazon S3 encrypts data with SSE-S3. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html">Protecting data with server-side encryption</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>S3 access points for Amazon FSx </b> - When accessing data stored in Amazon FSx file systems using S3 access points, the only valid server side encryption option is <code>aws:fsx</code>. All Amazon FSx file systems have encryption configured by default and are encrypted at rest. Data is automatically encrypted before being written to the file system, and automatically decrypted as it is read. These processes are handled transparently by Amazon FSx.</p>
    pub fn get_server_side_encryption(&self) -> &::std::option::Option<crate::types::ServerSideEncryption> {
        &self.server_side_encryption
    }
    /// <p>If you specify <code>x-amz-server-side-encryption</code> with <code>aws:kms</code>, you must specify the <code> x-amz-server-side-encryption-aws-kms-key-id</code> header with the ID (Key ID or Key ARN) of the KMS symmetric encryption customer managed key to use. Otherwise, you get an HTTP <code>400 Bad Request</code> error. Only use the key ID or key ARN. The key alias format of the KMS key isn't supported. Also, if the KMS key doesn't exist in the same account that't issuing the command, you must use the full Key ARN not the Key ID.</p>
    /// <p>Your SSE-KMS configuration can only support 1 <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk">customer managed key</a> per directory bucket's lifetime. The <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-cmk">Amazon Web Services managed key</a> (<code>aws/s3</code>) isn't supported.</p>
    pub fn ssekms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ssekms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you specify <code>x-amz-server-side-encryption</code> with <code>aws:kms</code>, you must specify the <code> x-amz-server-side-encryption-aws-kms-key-id</code> header with the ID (Key ID or Key ARN) of the KMS symmetric encryption customer managed key to use. Otherwise, you get an HTTP <code>400 Bad Request</code> error. Only use the key ID or key ARN. The key alias format of the KMS key isn't supported. Also, if the KMS key doesn't exist in the same account that't issuing the command, you must use the full Key ARN not the Key ID.</p>
    /// <p>Your SSE-KMS configuration can only support 1 <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk">customer managed key</a> per directory bucket's lifetime. The <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-cmk">Amazon Web Services managed key</a> (<code>aws/s3</code>) isn't supported.</p>
    pub fn set_ssekms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ssekms_key_id = input;
        self
    }
    /// <p>If you specify <code>x-amz-server-side-encryption</code> with <code>aws:kms</code>, you must specify the <code> x-amz-server-side-encryption-aws-kms-key-id</code> header with the ID (Key ID or Key ARN) of the KMS symmetric encryption customer managed key to use. Otherwise, you get an HTTP <code>400 Bad Request</code> error. Only use the key ID or key ARN. The key alias format of the KMS key isn't supported. Also, if the KMS key doesn't exist in the same account that't issuing the command, you must use the full Key ARN not the Key ID.</p>
    /// <p>Your SSE-KMS configuration can only support 1 <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk">customer managed key</a> per directory bucket's lifetime. The <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-cmk">Amazon Web Services managed key</a> (<code>aws/s3</code>) isn't supported.</p>
    pub fn get_ssekms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ssekms_key_id
    }
    /// <p>Specifies the Amazon Web Services KMS Encryption Context as an additional encryption context to use for object encryption. The value of this header is a Base64 encoded string of a UTF-8 encoded JSON, which contains the encryption context as key-value pairs. This value is stored as object metadata and automatically gets passed on to Amazon Web Services KMS for future <code>GetObject</code> operations on this object.</p>
    /// <p><b>General purpose buckets</b> - This value must be explicitly added during <code>CopyObject</code> operations if you want an additional encryption context for your object. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html#encryption-context">Encryption context</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>Directory buckets</b> - You can optionally provide an explicit encryption context value. The value must match the default encryption context - the bucket Amazon Resource Name (ARN). An additional encryption context value is not supported.</p>
    pub fn ssekms_encryption_context(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ssekms_encryption_context = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the Amazon Web Services KMS Encryption Context as an additional encryption context to use for object encryption. The value of this header is a Base64 encoded string of a UTF-8 encoded JSON, which contains the encryption context as key-value pairs. This value is stored as object metadata and automatically gets passed on to Amazon Web Services KMS for future <code>GetObject</code> operations on this object.</p>
    /// <p><b>General purpose buckets</b> - This value must be explicitly added during <code>CopyObject</code> operations if you want an additional encryption context for your object. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html#encryption-context">Encryption context</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>Directory buckets</b> - You can optionally provide an explicit encryption context value. The value must match the default encryption context - the bucket Amazon Resource Name (ARN). An additional encryption context value is not supported.</p>
    pub fn set_ssekms_encryption_context(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ssekms_encryption_context = input;
        self
    }
    /// <p>Specifies the Amazon Web Services KMS Encryption Context as an additional encryption context to use for object encryption. The value of this header is a Base64 encoded string of a UTF-8 encoded JSON, which contains the encryption context as key-value pairs. This value is stored as object metadata and automatically gets passed on to Amazon Web Services KMS for future <code>GetObject</code> operations on this object.</p>
    /// <p><b>General purpose buckets</b> - This value must be explicitly added during <code>CopyObject</code> operations if you want an additional encryption context for your object. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html#encryption-context">Encryption context</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p><b>Directory buckets</b> - You can optionally provide an explicit encryption context value. The value must match the default encryption context - the bucket Amazon Resource Name (ARN). An additional encryption context value is not supported.</p>
    pub fn get_ssekms_encryption_context(&self) -> &::std::option::Option<::std::string::String> {
        &self.ssekms_encryption_context
    }
    /// <p>Specifies whether Amazon S3 should use an S3 Bucket Key for object encryption with server-side encryption using KMS keys (SSE-KMS).</p>
    /// <p>S3 Bucket Keys are always enabled for <code>GET</code> and <code>PUT</code> operations in a directory bucket and can’t be disabled. S3 Bucket Keys aren't supported, when you copy SSE-KMS encrypted objects from general purpose buckets to directory buckets, from directory buckets to general purpose buckets, or between directory buckets, through <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html">CopyObject</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html">UploadPartCopy</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-objects-Batch-Ops">the Copy operation in Batch Operations</a>, or <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-import-job">the import jobs</a>. In this case, Amazon S3 makes a call to KMS every time a copy request is made for a KMS-encrypted object.</p>
    pub fn bucket_key_enabled(mut self, input: bool) -> Self {
        self.bucket_key_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether Amazon S3 should use an S3 Bucket Key for object encryption with server-side encryption using KMS keys (SSE-KMS).</p>
    /// <p>S3 Bucket Keys are always enabled for <code>GET</code> and <code>PUT</code> operations in a directory bucket and can’t be disabled. S3 Bucket Keys aren't supported, when you copy SSE-KMS encrypted objects from general purpose buckets to directory buckets, from directory buckets to general purpose buckets, or between directory buckets, through <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html">CopyObject</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html">UploadPartCopy</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-objects-Batch-Ops">the Copy operation in Batch Operations</a>, or <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-import-job">the import jobs</a>. In this case, Amazon S3 makes a call to KMS every time a copy request is made for a KMS-encrypted object.</p>
    pub fn set_bucket_key_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.bucket_key_enabled = input;
        self
    }
    /// <p>Specifies whether Amazon S3 should use an S3 Bucket Key for object encryption with server-side encryption using KMS keys (SSE-KMS).</p>
    /// <p>S3 Bucket Keys are always enabled for <code>GET</code> and <code>PUT</code> operations in a directory bucket and can’t be disabled. S3 Bucket Keys aren't supported, when you copy SSE-KMS encrypted objects from general purpose buckets to directory buckets, from directory buckets to general purpose buckets, or between directory buckets, through <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html">CopyObject</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html">UploadPartCopy</a>, <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-objects-Batch-Ops">the Copy operation in Batch Operations</a>, or <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-import-job">the import jobs</a>. In this case, Amazon S3 makes a call to KMS every time a copy request is made for a KMS-encrypted object.</p>
    pub fn get_bucket_key_enabled(&self) -> &::std::option::Option<bool> {
        &self.bucket_key_enabled
    }
    /// Consumes the builder and constructs a [`CreateSessionInput`](crate::operation::create_session::CreateSessionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_session::CreateSessionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_session::CreateSessionInput {
            session_mode: self.session_mode,
            bucket: self.bucket,
            server_side_encryption: self.server_side_encryption,
            ssekms_key_id: self.ssekms_key_id,
            ssekms_encryption_context: self.ssekms_encryption_context,
            bucket_key_enabled: self.bucket_key_enabled,
        })
    }
}
impl ::std::fmt::Debug for CreateSessionInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateSessionInputBuilder");
        formatter.field("session_mode", &self.session_mode);
        formatter.field("bucket", &self.bucket);
        formatter.field("server_side_encryption", &self.server_side_encryption);
        formatter.field("ssekms_key_id", &"*** Sensitive Data Redacted ***");
        formatter.field("ssekms_encryption_context", &"*** Sensitive Data Redacted ***");
        formatter.field("bucket_key_enabled", &self.bucket_key_enabled);
        formatter.finish()
    }
}
