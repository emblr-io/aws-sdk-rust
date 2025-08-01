// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The description of the server-side encryption status on the specified table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SseDescription {
    /// <p>Represents the current state of server-side encryption. The only supported values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> - Server-side encryption is enabled.</p></li>
    /// <li>
    /// <p><code>UPDATING</code> - Server-side encryption is being updated.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::SseStatus>,
    /// <p>Server-side encryption type. The only supported value is:</p>
    /// <ul>
    /// <li>
    /// <p><code>KMS</code> - Server-side encryption that uses Key Management Service. The key is stored in your account and is managed by KMS (KMS charges apply).</p></li>
    /// </ul>
    pub sse_type: ::std::option::Option<crate::types::SseType>,
    /// <p>The KMS key ARN used for the KMS encryption.</p>
    pub kms_master_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the time, in UNIX epoch date format, when DynamoDB detected that the table's KMS key was inaccessible. This attribute will automatically be cleared when DynamoDB detects that the table's KMS key is accessible again. DynamoDB will initiate the table archival process when table's KMS key remains inaccessible for more than seven days from this date.</p>
    pub inaccessible_encryption_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SseDescription {
    /// <p>Represents the current state of server-side encryption. The only supported values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> - Server-side encryption is enabled.</p></li>
    /// <li>
    /// <p><code>UPDATING</code> - Server-side encryption is being updated.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SseStatus> {
        self.status.as_ref()
    }
    /// <p>Server-side encryption type. The only supported value is:</p>
    /// <ul>
    /// <li>
    /// <p><code>KMS</code> - Server-side encryption that uses Key Management Service. The key is stored in your account and is managed by KMS (KMS charges apply).</p></li>
    /// </ul>
    pub fn sse_type(&self) -> ::std::option::Option<&crate::types::SseType> {
        self.sse_type.as_ref()
    }
    /// <p>The KMS key ARN used for the KMS encryption.</p>
    pub fn kms_master_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_master_key_arn.as_deref()
    }
    /// <p>Indicates the time, in UNIX epoch date format, when DynamoDB detected that the table's KMS key was inaccessible. This attribute will automatically be cleared when DynamoDB detects that the table's KMS key is accessible again. DynamoDB will initiate the table archival process when table's KMS key remains inaccessible for more than seven days from this date.</p>
    pub fn inaccessible_encryption_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.inaccessible_encryption_date_time.as_ref()
    }
}
impl SseDescription {
    /// Creates a new builder-style object to manufacture [`SseDescription`](crate::types::SseDescription).
    pub fn builder() -> crate::types::builders::SseDescriptionBuilder {
        crate::types::builders::SseDescriptionBuilder::default()
    }
}

/// A builder for [`SseDescription`](crate::types::SseDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SseDescriptionBuilder {
    pub(crate) status: ::std::option::Option<crate::types::SseStatus>,
    pub(crate) sse_type: ::std::option::Option<crate::types::SseType>,
    pub(crate) kms_master_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) inaccessible_encryption_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SseDescriptionBuilder {
    /// <p>Represents the current state of server-side encryption. The only supported values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> - Server-side encryption is enabled.</p></li>
    /// <li>
    /// <p><code>UPDATING</code> - Server-side encryption is being updated.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::SseStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents the current state of server-side encryption. The only supported values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> - Server-side encryption is enabled.</p></li>
    /// <li>
    /// <p><code>UPDATING</code> - Server-side encryption is being updated.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SseStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Represents the current state of server-side encryption. The only supported values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> - Server-side encryption is enabled.</p></li>
    /// <li>
    /// <p><code>UPDATING</code> - Server-side encryption is being updated.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SseStatus> {
        &self.status
    }
    /// <p>Server-side encryption type. The only supported value is:</p>
    /// <ul>
    /// <li>
    /// <p><code>KMS</code> - Server-side encryption that uses Key Management Service. The key is stored in your account and is managed by KMS (KMS charges apply).</p></li>
    /// </ul>
    pub fn sse_type(mut self, input: crate::types::SseType) -> Self {
        self.sse_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Server-side encryption type. The only supported value is:</p>
    /// <ul>
    /// <li>
    /// <p><code>KMS</code> - Server-side encryption that uses Key Management Service. The key is stored in your account and is managed by KMS (KMS charges apply).</p></li>
    /// </ul>
    pub fn set_sse_type(mut self, input: ::std::option::Option<crate::types::SseType>) -> Self {
        self.sse_type = input;
        self
    }
    /// <p>Server-side encryption type. The only supported value is:</p>
    /// <ul>
    /// <li>
    /// <p><code>KMS</code> - Server-side encryption that uses Key Management Service. The key is stored in your account and is managed by KMS (KMS charges apply).</p></li>
    /// </ul>
    pub fn get_sse_type(&self) -> &::std::option::Option<crate::types::SseType> {
        &self.sse_type
    }
    /// <p>The KMS key ARN used for the KMS encryption.</p>
    pub fn kms_master_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_master_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The KMS key ARN used for the KMS encryption.</p>
    pub fn set_kms_master_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_master_key_arn = input;
        self
    }
    /// <p>The KMS key ARN used for the KMS encryption.</p>
    pub fn get_kms_master_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_master_key_arn
    }
    /// <p>Indicates the time, in UNIX epoch date format, when DynamoDB detected that the table's KMS key was inaccessible. This attribute will automatically be cleared when DynamoDB detects that the table's KMS key is accessible again. DynamoDB will initiate the table archival process when table's KMS key remains inaccessible for more than seven days from this date.</p>
    pub fn inaccessible_encryption_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.inaccessible_encryption_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the time, in UNIX epoch date format, when DynamoDB detected that the table's KMS key was inaccessible. This attribute will automatically be cleared when DynamoDB detects that the table's KMS key is accessible again. DynamoDB will initiate the table archival process when table's KMS key remains inaccessible for more than seven days from this date.</p>
    pub fn set_inaccessible_encryption_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.inaccessible_encryption_date_time = input;
        self
    }
    /// <p>Indicates the time, in UNIX epoch date format, when DynamoDB detected that the table's KMS key was inaccessible. This attribute will automatically be cleared when DynamoDB detects that the table's KMS key is accessible again. DynamoDB will initiate the table archival process when table's KMS key remains inaccessible for more than seven days from this date.</p>
    pub fn get_inaccessible_encryption_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.inaccessible_encryption_date_time
    }
    /// Consumes the builder and constructs a [`SseDescription`](crate::types::SseDescription).
    pub fn build(self) -> crate::types::SseDescription {
        crate::types::SseDescription {
            status: self.status,
            sse_type: self.sse_type,
            kms_master_key_arn: self.kms_master_key_arn,
            inaccessible_encryption_date_time: self.inaccessible_encryption_date_time,
        }
    }
}
