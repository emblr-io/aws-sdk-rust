// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about an Amazon Web Services access key, without its secret key.</p>
/// <p>This data type is used as a response element in the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html">ListAccessKeys</a> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccessKeyMetadata {
    /// <p>The name of the IAM user that the key is associated with.</p>
    pub user_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID for this access key.</p>
    pub access_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the access key. <code>Active</code> means that the key is valid for API calls; <code>Inactive</code> means it is not.</p>
    pub status: ::std::option::Option<crate::types::StatusType>,
    /// <p>The date when the access key was created.</p>
    pub create_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AccessKeyMetadata {
    /// <p>The name of the IAM user that the key is associated with.</p>
    pub fn user_name(&self) -> ::std::option::Option<&str> {
        self.user_name.as_deref()
    }
    /// <p>The ID for this access key.</p>
    pub fn access_key_id(&self) -> ::std::option::Option<&str> {
        self.access_key_id.as_deref()
    }
    /// <p>The status of the access key. <code>Active</code> means that the key is valid for API calls; <code>Inactive</code> means it is not.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::StatusType> {
        self.status.as_ref()
    }
    /// <p>The date when the access key was created.</p>
    pub fn create_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_date.as_ref()
    }
}
impl AccessKeyMetadata {
    /// Creates a new builder-style object to manufacture [`AccessKeyMetadata`](crate::types::AccessKeyMetadata).
    pub fn builder() -> crate::types::builders::AccessKeyMetadataBuilder {
        crate::types::builders::AccessKeyMetadataBuilder::default()
    }
}

/// A builder for [`AccessKeyMetadata`](crate::types::AccessKeyMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccessKeyMetadataBuilder {
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
    pub(crate) access_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::StatusType>,
    pub(crate) create_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl AccessKeyMetadataBuilder {
    /// <p>The name of the IAM user that the key is associated with.</p>
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the IAM user that the key is associated with.</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>The name of the IAM user that the key is associated with.</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    /// <p>The ID for this access key.</p>
    pub fn access_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for this access key.</p>
    pub fn set_access_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_key_id = input;
        self
    }
    /// <p>The ID for this access key.</p>
    pub fn get_access_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_key_id
    }
    /// <p>The status of the access key. <code>Active</code> means that the key is valid for API calls; <code>Inactive</code> means it is not.</p>
    pub fn status(mut self, input: crate::types::StatusType) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the access key. <code>Active</code> means that the key is valid for API calls; <code>Inactive</code> means it is not.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::StatusType>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the access key. <code>Active</code> means that the key is valid for API calls; <code>Inactive</code> means it is not.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::StatusType> {
        &self.status
    }
    /// <p>The date when the access key was created.</p>
    pub fn create_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date when the access key was created.</p>
    pub fn set_create_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_date = input;
        self
    }
    /// <p>The date when the access key was created.</p>
    pub fn get_create_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_date
    }
    /// Consumes the builder and constructs a [`AccessKeyMetadata`](crate::types::AccessKeyMetadata).
    pub fn build(self) -> crate::types::AccessKeyMetadata {
        crate::types::AccessKeyMetadata {
            user_name: self.user_name,
            access_key_id: self.access_key_id,
            status: self.status,
            create_date: self.create_date,
        }
    }
}
