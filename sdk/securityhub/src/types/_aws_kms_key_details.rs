// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains metadata about an KMS key.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsKmsKeyDetails {
    /// <p>The twelve-digit account ID of the Amazon Web Services account that owns the KMS key.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>Indicates when the KMS key was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub creation_date: ::std::option::Option<f64>,
    /// <p>The globally unique identifier for the KMS key.</p>
    pub key_id: ::std::option::Option<::std::string::String>,
    /// <p>The manager of the KMS key. KMS keys in your Amazon Web Services account are either customer managed or Amazon Web Services managed.</p>
    pub key_manager: ::std::option::Option<::std::string::String>,
    /// <p>The state of the KMS key. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>Disabled</code></p></li>
    /// <li>
    /// <p><code>Enabled</code></p></li>
    /// <li>
    /// <p><code>PendingDeletion</code></p></li>
    /// <li>
    /// <p><code>PendingImport</code></p></li>
    /// <li>
    /// <p><code>Unavailable</code></p></li>
    /// </ul>
    pub key_state: ::std::option::Option<::std::string::String>,
    /// <p>The source of the KMS key material.</p>
    /// <p>When this value is <code>AWS_KMS</code>, KMS created the key material.</p>
    /// <p>When this value is <code>EXTERNAL</code>, the key material was imported from your existing key management infrastructure or the KMS key lacks key material.</p>
    /// <p>When this value is <code>AWS_CLOUDHSM</code>, the key material was created in the CloudHSM cluster associated with a custom key store.</p>
    pub origin: ::std::option::Option<::std::string::String>,
    /// <p>A description of the KMS key.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Whether the key has key rotation enabled.</p>
    pub key_rotation_status: ::std::option::Option<bool>,
}
impl AwsKmsKeyDetails {
    /// <p>The twelve-digit account ID of the Amazon Web Services account that owns the KMS key.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>Indicates when the KMS key was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn creation_date(&self) -> ::std::option::Option<f64> {
        self.creation_date
    }
    /// <p>The globally unique identifier for the KMS key.</p>
    pub fn key_id(&self) -> ::std::option::Option<&str> {
        self.key_id.as_deref()
    }
    /// <p>The manager of the KMS key. KMS keys in your Amazon Web Services account are either customer managed or Amazon Web Services managed.</p>
    pub fn key_manager(&self) -> ::std::option::Option<&str> {
        self.key_manager.as_deref()
    }
    /// <p>The state of the KMS key. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>Disabled</code></p></li>
    /// <li>
    /// <p><code>Enabled</code></p></li>
    /// <li>
    /// <p><code>PendingDeletion</code></p></li>
    /// <li>
    /// <p><code>PendingImport</code></p></li>
    /// <li>
    /// <p><code>Unavailable</code></p></li>
    /// </ul>
    pub fn key_state(&self) -> ::std::option::Option<&str> {
        self.key_state.as_deref()
    }
    /// <p>The source of the KMS key material.</p>
    /// <p>When this value is <code>AWS_KMS</code>, KMS created the key material.</p>
    /// <p>When this value is <code>EXTERNAL</code>, the key material was imported from your existing key management infrastructure or the KMS key lacks key material.</p>
    /// <p>When this value is <code>AWS_CLOUDHSM</code>, the key material was created in the CloudHSM cluster associated with a custom key store.</p>
    pub fn origin(&self) -> ::std::option::Option<&str> {
        self.origin.as_deref()
    }
    /// <p>A description of the KMS key.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Whether the key has key rotation enabled.</p>
    pub fn key_rotation_status(&self) -> ::std::option::Option<bool> {
        self.key_rotation_status
    }
}
impl AwsKmsKeyDetails {
    /// Creates a new builder-style object to manufacture [`AwsKmsKeyDetails`](crate::types::AwsKmsKeyDetails).
    pub fn builder() -> crate::types::builders::AwsKmsKeyDetailsBuilder {
        crate::types::builders::AwsKmsKeyDetailsBuilder::default()
    }
}

/// A builder for [`AwsKmsKeyDetails`](crate::types::AwsKmsKeyDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsKmsKeyDetailsBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<f64>,
    pub(crate) key_id: ::std::option::Option<::std::string::String>,
    pub(crate) key_manager: ::std::option::Option<::std::string::String>,
    pub(crate) key_state: ::std::option::Option<::std::string::String>,
    pub(crate) origin: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) key_rotation_status: ::std::option::Option<bool>,
}
impl AwsKmsKeyDetailsBuilder {
    /// <p>The twelve-digit account ID of the Amazon Web Services account that owns the KMS key.</p>
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The twelve-digit account ID of the Amazon Web Services account that owns the KMS key.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The twelve-digit account ID of the Amazon Web Services account that owns the KMS key.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>Indicates when the KMS key was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn creation_date(mut self, input: f64) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates when the KMS key was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<f64>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>Indicates when the KMS key was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<f64> {
        &self.creation_date
    }
    /// <p>The globally unique identifier for the KMS key.</p>
    pub fn key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The globally unique identifier for the KMS key.</p>
    pub fn set_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_id = input;
        self
    }
    /// <p>The globally unique identifier for the KMS key.</p>
    pub fn get_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_id
    }
    /// <p>The manager of the KMS key. KMS keys in your Amazon Web Services account are either customer managed or Amazon Web Services managed.</p>
    pub fn key_manager(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_manager = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The manager of the KMS key. KMS keys in your Amazon Web Services account are either customer managed or Amazon Web Services managed.</p>
    pub fn set_key_manager(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_manager = input;
        self
    }
    /// <p>The manager of the KMS key. KMS keys in your Amazon Web Services account are either customer managed or Amazon Web Services managed.</p>
    pub fn get_key_manager(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_manager
    }
    /// <p>The state of the KMS key. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>Disabled</code></p></li>
    /// <li>
    /// <p><code>Enabled</code></p></li>
    /// <li>
    /// <p><code>PendingDeletion</code></p></li>
    /// <li>
    /// <p><code>PendingImport</code></p></li>
    /// <li>
    /// <p><code>Unavailable</code></p></li>
    /// </ul>
    pub fn key_state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The state of the KMS key. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>Disabled</code></p></li>
    /// <li>
    /// <p><code>Enabled</code></p></li>
    /// <li>
    /// <p><code>PendingDeletion</code></p></li>
    /// <li>
    /// <p><code>PendingImport</code></p></li>
    /// <li>
    /// <p><code>Unavailable</code></p></li>
    /// </ul>
    pub fn set_key_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_state = input;
        self
    }
    /// <p>The state of the KMS key. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>Disabled</code></p></li>
    /// <li>
    /// <p><code>Enabled</code></p></li>
    /// <li>
    /// <p><code>PendingDeletion</code></p></li>
    /// <li>
    /// <p><code>PendingImport</code></p></li>
    /// <li>
    /// <p><code>Unavailable</code></p></li>
    /// </ul>
    pub fn get_key_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_state
    }
    /// <p>The source of the KMS key material.</p>
    /// <p>When this value is <code>AWS_KMS</code>, KMS created the key material.</p>
    /// <p>When this value is <code>EXTERNAL</code>, the key material was imported from your existing key management infrastructure or the KMS key lacks key material.</p>
    /// <p>When this value is <code>AWS_CLOUDHSM</code>, the key material was created in the CloudHSM cluster associated with a custom key store.</p>
    pub fn origin(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.origin = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source of the KMS key material.</p>
    /// <p>When this value is <code>AWS_KMS</code>, KMS created the key material.</p>
    /// <p>When this value is <code>EXTERNAL</code>, the key material was imported from your existing key management infrastructure or the KMS key lacks key material.</p>
    /// <p>When this value is <code>AWS_CLOUDHSM</code>, the key material was created in the CloudHSM cluster associated with a custom key store.</p>
    pub fn set_origin(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.origin = input;
        self
    }
    /// <p>The source of the KMS key material.</p>
    /// <p>When this value is <code>AWS_KMS</code>, KMS created the key material.</p>
    /// <p>When this value is <code>EXTERNAL</code>, the key material was imported from your existing key management infrastructure or the KMS key lacks key material.</p>
    /// <p>When this value is <code>AWS_CLOUDHSM</code>, the key material was created in the CloudHSM cluster associated with a custom key store.</p>
    pub fn get_origin(&self) -> &::std::option::Option<::std::string::String> {
        &self.origin
    }
    /// <p>A description of the KMS key.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the KMS key.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the KMS key.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Whether the key has key rotation enabled.</p>
    pub fn key_rotation_status(mut self, input: bool) -> Self {
        self.key_rotation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the key has key rotation enabled.</p>
    pub fn set_key_rotation_status(mut self, input: ::std::option::Option<bool>) -> Self {
        self.key_rotation_status = input;
        self
    }
    /// <p>Whether the key has key rotation enabled.</p>
    pub fn get_key_rotation_status(&self) -> &::std::option::Option<bool> {
        &self.key_rotation_status
    }
    /// Consumes the builder and constructs a [`AwsKmsKeyDetails`](crate::types::AwsKmsKeyDetails).
    pub fn build(self) -> crate::types::AwsKmsKeyDetails {
        crate::types::AwsKmsKeyDetails {
            aws_account_id: self.aws_account_id,
            creation_date: self.creation_date,
            key_id: self.key_id,
            key_manager: self.key_manager,
            key_state: self.key_state,
            origin: self.origin,
            description: self.description,
            key_rotation_status: self.key_rotation_status,
        }
    }
}
