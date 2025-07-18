// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFolderOutput {
    /// <p>The metadata of the folder.</p>
    pub metadata: ::std::option::Option<crate::types::FolderMetadata>,
    /// <p>The custom metadata on the folder.</p>
    pub custom_metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetFolderOutput {
    /// <p>The metadata of the folder.</p>
    pub fn metadata(&self) -> ::std::option::Option<&crate::types::FolderMetadata> {
        self.metadata.as_ref()
    }
    /// <p>The custom metadata on the folder.</p>
    pub fn custom_metadata(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.custom_metadata.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetFolderOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFolderOutput {
    /// Creates a new builder-style object to manufacture [`GetFolderOutput`](crate::operation::get_folder::GetFolderOutput).
    pub fn builder() -> crate::operation::get_folder::builders::GetFolderOutputBuilder {
        crate::operation::get_folder::builders::GetFolderOutputBuilder::default()
    }
}

/// A builder for [`GetFolderOutput`](crate::operation::get_folder::GetFolderOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFolderOutputBuilder {
    pub(crate) metadata: ::std::option::Option<crate::types::FolderMetadata>,
    pub(crate) custom_metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetFolderOutputBuilder {
    /// <p>The metadata of the folder.</p>
    pub fn metadata(mut self, input: crate::types::FolderMetadata) -> Self {
        self.metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metadata of the folder.</p>
    pub fn set_metadata(mut self, input: ::std::option::Option<crate::types::FolderMetadata>) -> Self {
        self.metadata = input;
        self
    }
    /// <p>The metadata of the folder.</p>
    pub fn get_metadata(&self) -> &::std::option::Option<crate::types::FolderMetadata> {
        &self.metadata
    }
    /// Adds a key-value pair to `custom_metadata`.
    ///
    /// To override the contents of this collection use [`set_custom_metadata`](Self::set_custom_metadata).
    ///
    /// <p>The custom metadata on the folder.</p>
    pub fn custom_metadata(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.custom_metadata.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.custom_metadata = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The custom metadata on the folder.</p>
    pub fn set_custom_metadata(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.custom_metadata = input;
        self
    }
    /// <p>The custom metadata on the folder.</p>
    pub fn get_custom_metadata(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.custom_metadata
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetFolderOutput`](crate::operation::get_folder::GetFolderOutput).
    pub fn build(self) -> crate::operation::get_folder::GetFolderOutput {
        crate::operation::get_folder::GetFolderOutput {
            metadata: self.metadata,
            custom_metadata: self.custom_metadata,
            _request_id: self._request_id,
        }
    }
}
