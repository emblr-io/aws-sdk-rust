// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagResourcesOutput {
    /// <p>A map containing a key-value pair for each failed item that couldn't be tagged. The key is the ARN of the failed resource. The value is a <code>FailureInfo</code> object that contains an error code, a status code, and an error message. If there are no errors, the <code>FailedResourcesMap</code> is empty.</p>
    pub failed_resources_map: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::FailureInfo>>,
    _request_id: Option<String>,
}
impl TagResourcesOutput {
    /// <p>A map containing a key-value pair for each failed item that couldn't be tagged. The key is the ARN of the failed resource. The value is a <code>FailureInfo</code> object that contains an error code, a status code, and an error message. If there are no errors, the <code>FailedResourcesMap</code> is empty.</p>
    pub fn failed_resources_map(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::FailureInfo>> {
        self.failed_resources_map.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for TagResourcesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl TagResourcesOutput {
    /// Creates a new builder-style object to manufacture [`TagResourcesOutput`](crate::operation::tag_resources::TagResourcesOutput).
    pub fn builder() -> crate::operation::tag_resources::builders::TagResourcesOutputBuilder {
        crate::operation::tag_resources::builders::TagResourcesOutputBuilder::default()
    }
}

/// A builder for [`TagResourcesOutput`](crate::operation::tag_resources::TagResourcesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagResourcesOutputBuilder {
    pub(crate) failed_resources_map: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::FailureInfo>>,
    _request_id: Option<String>,
}
impl TagResourcesOutputBuilder {
    /// Adds a key-value pair to `failed_resources_map`.
    ///
    /// To override the contents of this collection use [`set_failed_resources_map`](Self::set_failed_resources_map).
    ///
    /// <p>A map containing a key-value pair for each failed item that couldn't be tagged. The key is the ARN of the failed resource. The value is a <code>FailureInfo</code> object that contains an error code, a status code, and an error message. If there are no errors, the <code>FailedResourcesMap</code> is empty.</p>
    pub fn failed_resources_map(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::FailureInfo) -> Self {
        let mut hash_map = self.failed_resources_map.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.failed_resources_map = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map containing a key-value pair for each failed item that couldn't be tagged. The key is the ARN of the failed resource. The value is a <code>FailureInfo</code> object that contains an error code, a status code, and an error message. If there are no errors, the <code>FailedResourcesMap</code> is empty.</p>
    pub fn set_failed_resources_map(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::FailureInfo>>,
    ) -> Self {
        self.failed_resources_map = input;
        self
    }
    /// <p>A map containing a key-value pair for each failed item that couldn't be tagged. The key is the ARN of the failed resource. The value is a <code>FailureInfo</code> object that contains an error code, a status code, and an error message. If there are no errors, the <code>FailedResourcesMap</code> is empty.</p>
    pub fn get_failed_resources_map(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::FailureInfo>> {
        &self.failed_resources_map
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`TagResourcesOutput`](crate::operation::tag_resources::TagResourcesOutput).
    pub fn build(self) -> crate::operation::tag_resources::TagResourcesOutput {
        crate::operation::tag_resources::TagResourcesOutput {
            failed_resources_map: self.failed_resources_map,
            _request_id: self._request_id,
        }
    }
}
