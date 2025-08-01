// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSecretOutput {
    /// <p>The ARN of the new secret. The ARN includes the name of the secret followed by six random characters. This ensures that if you create a new secret with the same name as a deleted secret, then users with access to the old secret don't get access to the new secret because the ARNs are different.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the new secret.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier associated with the version of the new secret.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of the replicas of this secret and their status:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code>, which indicates that the replica was not created.</p></li>
    /// <li>
    /// <p><code>InProgress</code>, which indicates that Secrets Manager is in the process of creating the replica.</p></li>
    /// <li>
    /// <p><code>InSync</code>, which indicates that the replica was created.</p></li>
    /// </ul>
    pub replication_status: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationStatusType>>,
    _request_id: Option<String>,
}
impl CreateSecretOutput {
    /// <p>The ARN of the new secret. The ARN includes the name of the secret followed by six random characters. This ensures that if you create a new secret with the same name as a deleted secret, then users with access to the old secret don't get access to the new secret because the ARNs are different.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the new secret.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The unique identifier associated with the version of the new secret.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
    /// <p>A list of the replicas of this secret and their status:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code>, which indicates that the replica was not created.</p></li>
    /// <li>
    /// <p><code>InProgress</code>, which indicates that Secrets Manager is in the process of creating the replica.</p></li>
    /// <li>
    /// <p><code>InSync</code>, which indicates that the replica was created.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.replication_status.is_none()`.
    pub fn replication_status(&self) -> &[crate::types::ReplicationStatusType] {
        self.replication_status.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for CreateSecretOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateSecretOutput {
    /// Creates a new builder-style object to manufacture [`CreateSecretOutput`](crate::operation::create_secret::CreateSecretOutput).
    pub fn builder() -> crate::operation::create_secret::builders::CreateSecretOutputBuilder {
        crate::operation::create_secret::builders::CreateSecretOutputBuilder::default()
    }
}

/// A builder for [`CreateSecretOutput`](crate::operation::create_secret::CreateSecretOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSecretOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
    pub(crate) replication_status: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationStatusType>>,
    _request_id: Option<String>,
}
impl CreateSecretOutputBuilder {
    /// <p>The ARN of the new secret. The ARN includes the name of the secret followed by six random characters. This ensures that if you create a new secret with the same name as a deleted secret, then users with access to the old secret don't get access to the new secret because the ARNs are different.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the new secret. The ARN includes the name of the secret followed by six random characters. This ensures that if you create a new secret with the same name as a deleted secret, then users with access to the old secret don't get access to the new secret because the ARNs are different.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the new secret. The ARN includes the name of the secret followed by six random characters. This ensures that if you create a new secret with the same name as a deleted secret, then users with access to the old secret don't get access to the new secret because the ARNs are different.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the new secret.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the new secret.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the new secret.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The unique identifier associated with the version of the new secret.</p>
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier associated with the version of the new secret.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>The unique identifier associated with the version of the new secret.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// Appends an item to `replication_status`.
    ///
    /// To override the contents of this collection use [`set_replication_status`](Self::set_replication_status).
    ///
    /// <p>A list of the replicas of this secret and their status:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code>, which indicates that the replica was not created.</p></li>
    /// <li>
    /// <p><code>InProgress</code>, which indicates that Secrets Manager is in the process of creating the replica.</p></li>
    /// <li>
    /// <p><code>InSync</code>, which indicates that the replica was created.</p></li>
    /// </ul>
    pub fn replication_status(mut self, input: crate::types::ReplicationStatusType) -> Self {
        let mut v = self.replication_status.unwrap_or_default();
        v.push(input);
        self.replication_status = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the replicas of this secret and their status:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code>, which indicates that the replica was not created.</p></li>
    /// <li>
    /// <p><code>InProgress</code>, which indicates that Secrets Manager is in the process of creating the replica.</p></li>
    /// <li>
    /// <p><code>InSync</code>, which indicates that the replica was created.</p></li>
    /// </ul>
    pub fn set_replication_status(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationStatusType>>) -> Self {
        self.replication_status = input;
        self
    }
    /// <p>A list of the replicas of this secret and their status:</p>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code>, which indicates that the replica was not created.</p></li>
    /// <li>
    /// <p><code>InProgress</code>, which indicates that Secrets Manager is in the process of creating the replica.</p></li>
    /// <li>
    /// <p><code>InSync</code>, which indicates that the replica was created.</p></li>
    /// </ul>
    pub fn get_replication_status(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReplicationStatusType>> {
        &self.replication_status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateSecretOutput`](crate::operation::create_secret::CreateSecretOutput).
    pub fn build(self) -> crate::operation::create_secret::CreateSecretOutput {
        crate::operation::create_secret::CreateSecretOutput {
            arn: self.arn,
            name: self.name,
            version_id: self.version_id,
            replication_status: self.replication_status,
            _request_id: self._request_id,
        }
    }
}
