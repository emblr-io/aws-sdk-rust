// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOpsMetadataOutput {
    /// <p>The resource ID of the Application Manager application.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>OpsMetadata for an Application Manager application.</p>
    pub metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MetadataValue>>,
    /// <p>The token for the next set of items to return. Use this token to get the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetOpsMetadataOutput {
    /// <p>The resource ID of the Application Manager application.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>OpsMetadata for an Application Manager application.</p>
    pub fn metadata(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::MetadataValue>> {
        self.metadata.as_ref()
    }
    /// <p>The token for the next set of items to return. Use this token to get the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetOpsMetadataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetOpsMetadataOutput {
    /// Creates a new builder-style object to manufacture [`GetOpsMetadataOutput`](crate::operation::get_ops_metadata::GetOpsMetadataOutput).
    pub fn builder() -> crate::operation::get_ops_metadata::builders::GetOpsMetadataOutputBuilder {
        crate::operation::get_ops_metadata::builders::GetOpsMetadataOutputBuilder::default()
    }
}

/// A builder for [`GetOpsMetadataOutput`](crate::operation::get_ops_metadata::GetOpsMetadataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOpsMetadataOutputBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MetadataValue>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetOpsMetadataOutputBuilder {
    /// <p>The resource ID of the Application Manager application.</p>
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource ID of the Application Manager application.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The resource ID of the Application Manager application.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// Adds a key-value pair to `metadata`.
    ///
    /// To override the contents of this collection use [`set_metadata`](Self::set_metadata).
    ///
    /// <p>OpsMetadata for an Application Manager application.</p>
    pub fn metadata(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::MetadataValue) -> Self {
        let mut hash_map = self.metadata.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.metadata = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>OpsMetadata for an Application Manager application.</p>
    pub fn set_metadata(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MetadataValue>>,
    ) -> Self {
        self.metadata = input;
        self
    }
    /// <p>OpsMetadata for an Application Manager application.</p>
    pub fn get_metadata(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::MetadataValue>> {
        &self.metadata
    }
    /// <p>The token for the next set of items to return. Use this token to get the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of items to return. Use this token to get the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of items to return. Use this token to get the next set of results.</p>
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
    /// Consumes the builder and constructs a [`GetOpsMetadataOutput`](crate::operation::get_ops_metadata::GetOpsMetadataOutput).
    pub fn build(self) -> crate::operation::get_ops_metadata::GetOpsMetadataOutput {
        crate::operation::get_ops_metadata::GetOpsMetadataOutput {
            resource_id: self.resource_id,
            metadata: self.metadata,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
