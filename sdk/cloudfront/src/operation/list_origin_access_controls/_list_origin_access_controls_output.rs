// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListOriginAccessControlsOutput {
    /// <p>A list of origin access controls.</p>
    pub origin_access_control_list: ::std::option::Option<crate::types::OriginAccessControlList>,
    _request_id: Option<String>,
}
impl ListOriginAccessControlsOutput {
    /// <p>A list of origin access controls.</p>
    pub fn origin_access_control_list(&self) -> ::std::option::Option<&crate::types::OriginAccessControlList> {
        self.origin_access_control_list.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ListOriginAccessControlsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListOriginAccessControlsOutput {
    /// Creates a new builder-style object to manufacture [`ListOriginAccessControlsOutput`](crate::operation::list_origin_access_controls::ListOriginAccessControlsOutput).
    pub fn builder() -> crate::operation::list_origin_access_controls::builders::ListOriginAccessControlsOutputBuilder {
        crate::operation::list_origin_access_controls::builders::ListOriginAccessControlsOutputBuilder::default()
    }
}

/// A builder for [`ListOriginAccessControlsOutput`](crate::operation::list_origin_access_controls::ListOriginAccessControlsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListOriginAccessControlsOutputBuilder {
    pub(crate) origin_access_control_list: ::std::option::Option<crate::types::OriginAccessControlList>,
    _request_id: Option<String>,
}
impl ListOriginAccessControlsOutputBuilder {
    /// <p>A list of origin access controls.</p>
    pub fn origin_access_control_list(mut self, input: crate::types::OriginAccessControlList) -> Self {
        self.origin_access_control_list = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of origin access controls.</p>
    pub fn set_origin_access_control_list(mut self, input: ::std::option::Option<crate::types::OriginAccessControlList>) -> Self {
        self.origin_access_control_list = input;
        self
    }
    /// <p>A list of origin access controls.</p>
    pub fn get_origin_access_control_list(&self) -> &::std::option::Option<crate::types::OriginAccessControlList> {
        &self.origin_access_control_list
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListOriginAccessControlsOutput`](crate::operation::list_origin_access_controls::ListOriginAccessControlsOutput).
    pub fn build(self) -> crate::operation::list_origin_access_controls::ListOriginAccessControlsOutput {
        crate::operation::list_origin_access_controls::ListOriginAccessControlsOutput {
            origin_access_control_list: self.origin_access_control_list,
            _request_id: self._request_id,
        }
    }
}
