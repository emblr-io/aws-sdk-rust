// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListStorageConfigurationsOutput {
    /// <p>List of the matching storage configurations.</p>
    pub storage_configurations: ::std::vec::Vec<crate::types::StorageConfigurationSummary>,
    /// <p>If there are more storage configurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListStorageConfigurationsOutput {
    /// <p>List of the matching storage configurations.</p>
    pub fn storage_configurations(&self) -> &[crate::types::StorageConfigurationSummary] {
        use std::ops::Deref;
        self.storage_configurations.deref()
    }
    /// <p>If there are more storage configurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListStorageConfigurationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListStorageConfigurationsOutput {
    /// Creates a new builder-style object to manufacture [`ListStorageConfigurationsOutput`](crate::operation::list_storage_configurations::ListStorageConfigurationsOutput).
    pub fn builder() -> crate::operation::list_storage_configurations::builders::ListStorageConfigurationsOutputBuilder {
        crate::operation::list_storage_configurations::builders::ListStorageConfigurationsOutputBuilder::default()
    }
}

/// A builder for [`ListStorageConfigurationsOutput`](crate::operation::list_storage_configurations::ListStorageConfigurationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListStorageConfigurationsOutputBuilder {
    pub(crate) storage_configurations: ::std::option::Option<::std::vec::Vec<crate::types::StorageConfigurationSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListStorageConfigurationsOutputBuilder {
    /// Appends an item to `storage_configurations`.
    ///
    /// To override the contents of this collection use [`set_storage_configurations`](Self::set_storage_configurations).
    ///
    /// <p>List of the matching storage configurations.</p>
    pub fn storage_configurations(mut self, input: crate::types::StorageConfigurationSummary) -> Self {
        let mut v = self.storage_configurations.unwrap_or_default();
        v.push(input);
        self.storage_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of the matching storage configurations.</p>
    pub fn set_storage_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StorageConfigurationSummary>>) -> Self {
        self.storage_configurations = input;
        self
    }
    /// <p>List of the matching storage configurations.</p>
    pub fn get_storage_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StorageConfigurationSummary>> {
        &self.storage_configurations
    }
    /// <p>If there are more storage configurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are more storage configurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are more storage configurations than <code>maxResults</code>, use <code>nextToken</code> in the request to get the next set.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListStorageConfigurationsOutput`](crate::operation::list_storage_configurations::ListStorageConfigurationsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`storage_configurations`](crate::operation::list_storage_configurations::builders::ListStorageConfigurationsOutputBuilder::storage_configurations)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_storage_configurations::ListStorageConfigurationsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_storage_configurations::ListStorageConfigurationsOutput {
            storage_configurations: self.storage_configurations.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "storage_configurations",
                    "storage_configurations was not specified but it is required when building ListStorageConfigurationsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
