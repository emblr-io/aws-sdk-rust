// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyInstanceMetadataDefaultsOutput {
    /// <p>If the request succeeds, the response returns <code>true</code>. If the request fails, no response is returned, and instead an error message is returned.</p>
    pub r#return: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl ModifyInstanceMetadataDefaultsOutput {
    /// <p>If the request succeeds, the response returns <code>true</code>. If the request fails, no response is returned, and instead an error message is returned.</p>
    pub fn r#return(&self) -> ::std::option::Option<bool> {
        self.r#return
    }
}
impl ::aws_types::request_id::RequestId for ModifyInstanceMetadataDefaultsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyInstanceMetadataDefaultsOutput {
    /// Creates a new builder-style object to manufacture [`ModifyInstanceMetadataDefaultsOutput`](crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsOutput).
    pub fn builder() -> crate::operation::modify_instance_metadata_defaults::builders::ModifyInstanceMetadataDefaultsOutputBuilder {
        crate::operation::modify_instance_metadata_defaults::builders::ModifyInstanceMetadataDefaultsOutputBuilder::default()
    }
}

/// A builder for [`ModifyInstanceMetadataDefaultsOutput`](crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyInstanceMetadataDefaultsOutputBuilder {
    pub(crate) r#return: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl ModifyInstanceMetadataDefaultsOutputBuilder {
    /// <p>If the request succeeds, the response returns <code>true</code>. If the request fails, no response is returned, and instead an error message is returned.</p>
    pub fn r#return(mut self, input: bool) -> Self {
        self.r#return = ::std::option::Option::Some(input);
        self
    }
    /// <p>If the request succeeds, the response returns <code>true</code>. If the request fails, no response is returned, and instead an error message is returned.</p>
    pub fn set_return(mut self, input: ::std::option::Option<bool>) -> Self {
        self.r#return = input;
        self
    }
    /// <p>If the request succeeds, the response returns <code>true</code>. If the request fails, no response is returned, and instead an error message is returned.</p>
    pub fn get_return(&self) -> &::std::option::Option<bool> {
        &self.r#return
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyInstanceMetadataDefaultsOutput`](crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsOutput).
    pub fn build(self) -> crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsOutput {
        crate::operation::modify_instance_metadata_defaults::ModifyInstanceMetadataDefaultsOutput {
            r#return: self.r#return,
            _request_id: self._request_id,
        }
    }
}
