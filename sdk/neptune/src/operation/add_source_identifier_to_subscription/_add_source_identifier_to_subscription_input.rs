// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddSourceIdentifierToSubscriptionInput {
    /// <p>The name of the event notification subscription you want to add a source identifier to.</p>
    pub subscription_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the event source to be added.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If the source type is a DB instance, then a <code>DBInstanceIdentifier</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB security group, a <code>DBSecurityGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB parameter group, a <code>DBParameterGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB snapshot, a <code>DBSnapshotIdentifier</code> must be supplied.</p></li>
    /// </ul>
    pub source_identifier: ::std::option::Option<::std::string::String>,
}
impl AddSourceIdentifierToSubscriptionInput {
    /// <p>The name of the event notification subscription you want to add a source identifier to.</p>
    pub fn subscription_name(&self) -> ::std::option::Option<&str> {
        self.subscription_name.as_deref()
    }
    /// <p>The identifier of the event source to be added.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If the source type is a DB instance, then a <code>DBInstanceIdentifier</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB security group, a <code>DBSecurityGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB parameter group, a <code>DBParameterGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB snapshot, a <code>DBSnapshotIdentifier</code> must be supplied.</p></li>
    /// </ul>
    pub fn source_identifier(&self) -> ::std::option::Option<&str> {
        self.source_identifier.as_deref()
    }
}
impl AddSourceIdentifierToSubscriptionInput {
    /// Creates a new builder-style object to manufacture [`AddSourceIdentifierToSubscriptionInput`](crate::operation::add_source_identifier_to_subscription::AddSourceIdentifierToSubscriptionInput).
    pub fn builder() -> crate::operation::add_source_identifier_to_subscription::builders::AddSourceIdentifierToSubscriptionInputBuilder {
        crate::operation::add_source_identifier_to_subscription::builders::AddSourceIdentifierToSubscriptionInputBuilder::default()
    }
}

/// A builder for [`AddSourceIdentifierToSubscriptionInput`](crate::operation::add_source_identifier_to_subscription::AddSourceIdentifierToSubscriptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddSourceIdentifierToSubscriptionInputBuilder {
    pub(crate) subscription_name: ::std::option::Option<::std::string::String>,
    pub(crate) source_identifier: ::std::option::Option<::std::string::String>,
}
impl AddSourceIdentifierToSubscriptionInputBuilder {
    /// <p>The name of the event notification subscription you want to add a source identifier to.</p>
    /// This field is required.
    pub fn subscription_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subscription_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the event notification subscription you want to add a source identifier to.</p>
    pub fn set_subscription_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subscription_name = input;
        self
    }
    /// <p>The name of the event notification subscription you want to add a source identifier to.</p>
    pub fn get_subscription_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.subscription_name
    }
    /// <p>The identifier of the event source to be added.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If the source type is a DB instance, then a <code>DBInstanceIdentifier</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB security group, a <code>DBSecurityGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB parameter group, a <code>DBParameterGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB snapshot, a <code>DBSnapshotIdentifier</code> must be supplied.</p></li>
    /// </ul>
    /// This field is required.
    pub fn source_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the event source to be added.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If the source type is a DB instance, then a <code>DBInstanceIdentifier</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB security group, a <code>DBSecurityGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB parameter group, a <code>DBParameterGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB snapshot, a <code>DBSnapshotIdentifier</code> must be supplied.</p></li>
    /// </ul>
    pub fn set_source_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_identifier = input;
        self
    }
    /// <p>The identifier of the event source to be added.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If the source type is a DB instance, then a <code>DBInstanceIdentifier</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB security group, a <code>DBSecurityGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB parameter group, a <code>DBParameterGroupName</code> must be supplied.</p></li>
    /// <li>
    /// <p>If the source type is a DB snapshot, a <code>DBSnapshotIdentifier</code> must be supplied.</p></li>
    /// </ul>
    pub fn get_source_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_identifier
    }
    /// Consumes the builder and constructs a [`AddSourceIdentifierToSubscriptionInput`](crate::operation::add_source_identifier_to_subscription::AddSourceIdentifierToSubscriptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::add_source_identifier_to_subscription::AddSourceIdentifierToSubscriptionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::add_source_identifier_to_subscription::AddSourceIdentifierToSubscriptionInput {
                subscription_name: self.subscription_name,
                source_identifier: self.source_identifier,
            },
        )
    }
}
