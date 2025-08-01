// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDefaultRetentionPolicyOutput {
    /// <p>The retention policy ID.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The retention policy name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The retention policy description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The retention policy folder configurations.</p>
    pub folder_configurations: ::std::option::Option<::std::vec::Vec<crate::types::FolderConfiguration>>,
    _request_id: Option<String>,
}
impl GetDefaultRetentionPolicyOutput {
    /// <p>The retention policy ID.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The retention policy name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The retention policy description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The retention policy folder configurations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.folder_configurations.is_none()`.
    pub fn folder_configurations(&self) -> &[crate::types::FolderConfiguration] {
        self.folder_configurations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetDefaultRetentionPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDefaultRetentionPolicyOutput {
    /// Creates a new builder-style object to manufacture [`GetDefaultRetentionPolicyOutput`](crate::operation::get_default_retention_policy::GetDefaultRetentionPolicyOutput).
    pub fn builder() -> crate::operation::get_default_retention_policy::builders::GetDefaultRetentionPolicyOutputBuilder {
        crate::operation::get_default_retention_policy::builders::GetDefaultRetentionPolicyOutputBuilder::default()
    }
}

/// A builder for [`GetDefaultRetentionPolicyOutput`](crate::operation::get_default_retention_policy::GetDefaultRetentionPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDefaultRetentionPolicyOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) folder_configurations: ::std::option::Option<::std::vec::Vec<crate::types::FolderConfiguration>>,
    _request_id: Option<String>,
}
impl GetDefaultRetentionPolicyOutputBuilder {
    /// <p>The retention policy ID.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The retention policy ID.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The retention policy ID.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The retention policy name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The retention policy name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The retention policy name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The retention policy description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The retention policy description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The retention policy description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `folder_configurations`.
    ///
    /// To override the contents of this collection use [`set_folder_configurations`](Self::set_folder_configurations).
    ///
    /// <p>The retention policy folder configurations.</p>
    pub fn folder_configurations(mut self, input: crate::types::FolderConfiguration) -> Self {
        let mut v = self.folder_configurations.unwrap_or_default();
        v.push(input);
        self.folder_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The retention policy folder configurations.</p>
    pub fn set_folder_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FolderConfiguration>>) -> Self {
        self.folder_configurations = input;
        self
    }
    /// <p>The retention policy folder configurations.</p>
    pub fn get_folder_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FolderConfiguration>> {
        &self.folder_configurations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDefaultRetentionPolicyOutput`](crate::operation::get_default_retention_policy::GetDefaultRetentionPolicyOutput).
    pub fn build(self) -> crate::operation::get_default_retention_policy::GetDefaultRetentionPolicyOutput {
        crate::operation::get_default_retention_policy::GetDefaultRetentionPolicyOutput {
            id: self.id,
            name: self.name,
            description: self.description,
            folder_configurations: self.folder_configurations,
            _request_id: self._request_id,
        }
    }
}
